package c2pa

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/asn1"
	"os"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	cose "github.com/veraison/go-cose"
)

// fixtureSigningPool builds a trust pool anchored at the top certificate of the
// fixture's own COSE x5chain (its intermediate CA). The c2pa-rs test fixture is
// signed by a private test PKI whose root is not in the production trust list,
// so positive tests anchor at the chain the fixture itself carries rather than
// shipping the test root.
func fixtureSigningPool(t *testing.T) (*x509.CertPool, []byte) {
	t.Helper()
	data, err := os.ReadFile("testdata/c2pa_signed.jpg")
	if err != nil {
		t.Fatal(err)
	}
	jumbf := extractJUMBF(context.Background(), JPEG, data)
	m := parseStore(context.Background(), jumbf).active()
	if m == nil || len(m.signature) == 0 {
		t.Fatal("fixture has no signature")
	}
	var msg cose.Sign1Message
	if err := msg.UnmarshalCBOR(m.signature); err != nil {
		t.Fatalf("decode COSE: %v", err)
	}
	chain := parseChain(msg.Headers.Protected[cose.HeaderLabelX5Chain])
	if len(chain) == 0 {
		t.Fatal("fixture has no x5chain")
	}
	pool := x509.NewCertPool()
	pool.AddCert(chain[len(chain)-1]) // anchor at the top (intermediate) cert
	return pool, data
}

// fixtureTimestampPool builds a trust pool anchored at the self-signed root of
// the fixture's RFC 3161 timestamp token (DigiCert Trusted Root G4), so the
// timestamp validates without depending on the production TSA list's contents.
func fixtureTimestampPool(t *testing.T) *x509.CertPool {
	t.Helper()
	data, err := os.ReadFile("testdata/c2pa_signed.jpg")
	if err != nil {
		t.Fatal(err)
	}
	jumbf := extractJUMBF(context.Background(), JPEG, data)
	m := parseStore(context.Background(), jumbf).active()
	var msg cose.Sign1Message
	if err := msg.UnmarshalCBOR(m.signature); err != nil {
		t.Fatal(err)
	}
	der, _ := extractTSToken(msg.Headers.Unprotected)
	sd, ok := parseCMSSignedData(der)
	if !ok {
		t.Fatal("could not parse timestamp token")
	}
	// The token's top certificate (here a cross-signed DigiCert Trusted Root G4)
	// is the one whose issuer is not the subject of any other cert in the set.
	// Anchor there. x509.Verify accepts any pool cert as an anchor, regardless
	// of self-signed status.
	subjects := map[string]bool{}
	for _, c := range sd.certs {
		subjects[string(c.RawSubject)] = true
	}
	pool := x509.NewCertPool()
	for _, c := range sd.certs {
		if !subjects[string(c.RawIssuer)] {
			pool.AddCert(c)
		}
	}
	return pool
}

// TestParseStore_SignedJPEG confirms the manifest-store resolver navigates the
// real fixture: it should find one manifest with claim bytes, COSE signature
// bytes, and a hard-binding hash assertion among its assertions.
func TestParseStore_SignedJPEG(t *testing.T) {
	data, err := os.ReadFile("testdata/c2pa_signed.jpg")
	if err != nil {
		t.Fatal(err)
	}
	jumbf := extractJUMBF(context.Background(), JPEG, data)
	if len(jumbf) == 0 {
		t.Fatal("no JUMBF extracted")
	}
	store := parseStore(context.Background(), jumbf)
	m := store.active()
	if m == nil {
		t.Fatal("no active manifest")
	}
	if len(m.claimBytes) == 0 {
		t.Error("claim bytes empty")
	}
	if m.claim == nil {
		t.Error("claim did not decode")
	}
	if len(m.signature) == 0 {
		t.Error("signature bytes empty")
	}
	if len(m.assertions) == 0 {
		t.Fatal("no assertions found")
	}
	var labels []string
	hasHardBinding := false
	for _, a := range m.assertions {
		labels = append(labels, a.label)
		if a.label == "c2pa.hash.data" || a.label == "c2pa.hash.boxes" {
			hasHardBinding = true
		}
		if len(a.boxContent) == 0 || len(a.data) == 0 {
			t.Errorf("assertion %q has empty bytes (boxContent=%d data=%d)", a.label, len(a.boxContent), len(a.data))
		}
	}
	t.Logf("manifest=%q assertions=%v", m.label, labels)
	if !hasHardBinding {
		t.Errorf("expected a c2pa.hash.* hard-binding assertion, got %v", labels)
	}
}

// TestValidate_Signature verifies the COSE signature and certificate chain of
// the fixture against a pool anchored at its own chain.
func TestValidate_Signature(t *testing.T) {
	pool, data := fixtureSigningPool(t)
	r := Validate(context.Background(), JPEG, bytes.NewReader(data), WithSigningTrust(pool))

	if !r.Has(StatusClaimSignatureValidated) {
		t.Errorf("expected claim signature to validate; statuses=%v", codes(r))
	}
	if !r.Has(StatusSigningCredentialTrusted) {
		t.Errorf("expected signing credential trusted; statuses=%v", codes(r))
	}
	if r.Info.SignedBy != "C2PA Signer" {
		t.Errorf("Info.SignedBy=%q want %q", r.Info.SignedBy, "C2PA Signer")
	}
	if len(r.SignerChain) != 2 {
		t.Errorf("SignerChain len=%d want 2", len(r.SignerChain))
	}
}

// TestValidate_Timestamp verifies the RFC 3161 timestamp end-to-end: the CMS
// signature, the messageImprint binding to the COSE signature, and the TSA
// chain to the token's own root, surfacing the verified SignedAt.
func TestValidate_Timestamp(t *testing.T) {
	pool, data := fixtureSigningPool(t)
	tsaPool := fixtureTimestampPool(t)
	r := Validate(context.Background(), JPEG, bytes.NewReader(data),
		WithSigningTrust(pool), WithTimestampTrust(tsaPool))

	if !r.Has(StatusTimeStampValidated) {
		t.Errorf("expected timeStamp.validated; got %v", codes(r))
	}
	want := time.Date(2024, 8, 6, 21, 53, 37, 0, time.UTC)
	if !r.SignedAt.Equal(want) {
		t.Errorf("SignedAt=%s want %s", r.SignedAt.Format(time.RFC3339), want.Format(time.RFC3339))
	}
	if !r.Valid {
		t.Errorf("expected Valid=true; first failure=%+v", r.FirstFailure())
	}
}

// TestTimestampBareContentInfo checks the token shape C2PA actually writes. The
// fixture's sigTst holds a full TimeStampResp, but sigTst/sigTst2 may hold the
// bare ContentInfo inside it, which is what Google's and OpenAI's images carry.
// Unwrapping the fixture's own token yields that shape, so both can be put
// through the same verification.
func TestTimestampBareContentInfo(t *testing.T) {
	wrapped, tbs := fixtureTSToken(t)

	var resp struct {
		Status asn1.RawValue
		Token  asn1.RawValue `asn1:"optional"`
	}
	if _, err := asn1.Unmarshal(wrapped, &resp); err != nil {
		t.Fatalf("fixture token is not a TimeStampResp: %v", err)
	}
	// The probe above matches any two-element SEQUENCE, a bare ContentInfo
	// included, so an OID first element means the fixture is already the shape
	// this test means to derive and Token is really the [0] content wrapper.
	var contentType asn1.ObjectIdentifier
	if _, err := asn1.Unmarshal(resp.Status.FullBytes, &contentType); err == nil {
		t.Fatal("fixture token is a bare ContentInfo, not a TimeStampResp to unwrap")
	}
	bare := resp.Token.FullBytes
	if len(bare) == 0 {
		t.Fatal("fixture token carries no timeStampToken")
	}

	// Read's descent must reach the same genTime for either shape.
	want := rfc3161GenTime(wrapped)
	if want.IsZero() {
		t.Fatal("rfc3161GenTime failed on the wrapped token")
	}
	if got := rfc3161GenTime(bare); !got.Equal(want) {
		t.Errorf("rfc3161GenTime(bare)=%s want %s", got, want)
	}

	// Validate's must fully verify either shape — messageImprint, CMS signature,
	// signed attributes and TSA chain — not merely parse it.
	tsaPool := fixtureTimestampPool(t)
	for _, tc := range []struct {
		name string
		der  []byte
	}{{"TimeStampResp", wrapped}, {"bare ContentInfo", bare}} {
		v := &validator{ctx: context.Background(), cfg: validateConfig{timestampTrust: tsaPool}}
		gt, code := v.verifyTimestampToken(tc.der, tbs, "self#jumbf=/c2pa")
		if code != StatusTimeStampValidated {
			t.Errorf("%s: code=%v want %v; statuses=%v", tc.name, code, StatusTimeStampValidated, v.res.Statuses)
			continue
		}
		if !gt.Equal(want) {
			t.Errorf("%s: genTime=%s want %s", tc.name, gt, want)
		}
	}
}

// fixtureTSToken returns the raw RFC 3161 token embedded in the fixture's COSE
// signature, and the bytes that token counter-signs.
func fixtureTSToken(t *testing.T) (der, tbs []byte) {
	t.Helper()
	data, err := os.ReadFile("testdata/c2pa_signed.jpg")
	if err != nil {
		t.Fatal(err)
	}
	jumbf := extractJUMBF(context.Background(), JPEG, data)
	m := parseStore(context.Background(), jumbf).active()
	if m == nil {
		t.Fatal("fixture has no manifest")
	}
	var msg cose.Sign1Message
	if err := msg.UnmarshalCBOR(m.signature); err != nil {
		t.Fatal(err)
	}
	der, v2 := extractTSToken(msg.Headers.Unprotected)
	if len(der) == 0 {
		t.Fatal("fixture has no timestamp token")
	}
	protected, signature, ok := coseParts(m.signature)
	if !ok {
		t.Fatal("could not decode the fixture's COSE structure")
	}
	counterPayload := m.claimBytes
	if v2 {
		counterPayload, _ = cbor.Marshal(signature)
	}
	return der, coseCountersignData(counterPayload, protected)
}

// TestSigningTimeBothTimestampHeaders checks Read reaches the timestamp in
// either container. C2PA 1.x puts it in sigTst; a c2pa.claim.v2 signature puts
// it in sigTst2, which is what Google's and OpenAI's images carry, so reading
// only sigTst leaves Info.SignedAt zero for every 2.x file.
func TestSigningTimeBothTimestampHeaders(t *testing.T) {
	der, _ := fixtureTSToken(t)
	want := rfc3161GenTime(der)
	if want.IsZero() {
		t.Fatal("fixture token has no genTime")
	}
	for _, name := range []string{"sigTst", "sigTst2"} {
		unprotected := map[any]any{
			name: map[any]any{"tstTokens": []any{map[any]any{"val": der}}},
		}
		if got := signingTime(unprotected); !got.Equal(want) {
			t.Errorf("signingTime(%s)=%s want %s", name, got, want)
		}
	}
}

// TestC2PA2xOpenAIFixture puts all three fixes on a real C2PA 2.x file, which
// no synthesised test can do: a single-entry claim_generator_info, a
// softwareAgent naming the model, and a bare ContentInfo timestamp that lives in
// sigTst2 with no sigTst present at all.
func TestC2PA2xOpenAIFixture(t *testing.T) {
	data, err := os.ReadFile("testdata/c2pa_2x_openai.png")
	if err != nil {
		t.Fatal(err)
	}
	signedAt := time.Date(2026, 8, 26, 10, 48, 55, 837381000, time.UTC)

	info := Read(context.Background(), PNG, bytes.NewReader(data))
	for _, tc := range []struct{ name, got, want string }{
		{"ClaimGenerator", info.ClaimGenerator, "OpenAI Media Service API"},
		{"SoftwareAgent", info.SoftwareAgent, "gpt-image/2.0"},
		{"Title", info.Title, "image.png"},
		{"SignedBy", info.SignedBy, "OpenAI Media Service"},
	} {
		if tc.got != tc.want {
			t.Errorf("Read %s=%q want %q", tc.name, tc.got, tc.want)
		}
	}
	if !info.AIGenerated {
		t.Error("Read AIGenerated=false, want true")
	}
	// Zero here before the descent handled a bare ContentInfo, and zero again
	// while signingTime read only sigTst.
	if !info.SignedAt.Equal(signedAt) {
		t.Errorf("Read SignedAt=%s want %s", info.SignedAt, signedAt)
	}

	// The clock is pinned to the signing time: the leaf expires 2027-04-23, and
	// the timestamp is untrusted so it cannot pin the window itself.
	r := Validate(context.Background(), PNG, bytes.NewReader(data),
		WithClock(func() time.Time { return signedAt }))

	for _, code := range []StatusCode{StatusClaimSignatureValidated, StatusSigningCredentialTrusted} {
		if !r.Has(code) {
			t.Errorf("expected %s; statuses=%v", code, codes(r))
		}
	}
	// The manifest still binds these exact bytes.
	for _, code := range []StatusCode{StatusAssertionDataHashMismatch, StatusHardBindingMissing} {
		if r.Has(code) {
			t.Errorf("unexpected %s; statuses=%v", code, codes(r))
		}
	}
	// The fix, on a real file: the token is no longer read as malformed. It
	// lands on timeStamp.untrusted instead, because OpenAI timestamps with its
	// own private TSA root, so that is deliberately not asserted here — a trust
	// list that later carries that root must not fail this test.
	if r.Has(StatusTimeStampMismatch) {
		t.Errorf("timestamp still rejected as malformed; first failure=%+v", r.FirstFailure())
	}
	if len(r.SignerChain) != 2 {
		t.Errorf("SignerChain len=%d want 2", len(r.SignerChain))
	}
}

// TestValidate_TamperedTimestamp corrupts the timestamp token so CMS
// verification fails.
func TestValidate_TamperedTimestamp(t *testing.T) {
	pool, data := fixtureSigningPool(t)
	tsaPool := fixtureTimestampPool(t)
	// Flip a byte inside the timestamp token as embedded in the file. The token
	// is within the (excluded) manifest region, so the data hash still matches;
	// only the timestamp should break.
	jumbf := extractJUMBF(context.Background(), JPEG, data)
	m := parseStore(context.Background(), jumbf).active()
	var msg cose.Sign1Message
	if err := msg.UnmarshalCBOR(m.signature); err != nil {
		t.Fatal(err)
	}
	der, _ := extractTSToken(msg.Headers.Unprotected)
	idx := bytes.Index(data, der)
	if idx < 0 {
		t.Skip("timestamp token not contiguous in file")
	}
	tampered := append([]byte(nil), data...)
	tampered[idx+len(der)-20] ^= 0xFF
	r := Validate(context.Background(), JPEG, bytes.NewReader(tampered),
		WithSigningTrust(pool), WithTimestampTrust(tsaPool))
	if r.Has(StatusTimeStampValidated) {
		t.Errorf("expected timestamp NOT validated; got %v", codes(r))
	}
}

// TestValidate_UntrustedAgainstProductionList confirms the test-PKI fixture is
// reported untrusted against the embedded official trust list (default pool).
func TestValidate_UntrustedAgainstProductionList(t *testing.T) {
	data, err := os.ReadFile("testdata/c2pa_signed.jpg")
	if err != nil {
		t.Fatal(err)
	}
	r := Validate(context.Background(), JPEG, bytes.NewReader(data))
	// Signature itself still verifies (claim integrity), but the chain does not
	// reach a production anchor.
	if !r.Has(StatusClaimSignatureValidated) {
		t.Errorf("expected signature to still validate; statuses=%v", codes(r))
	}
	if !r.Has(StatusSigningCredentialUntrusted) {
		t.Errorf("expected signingCredential.untrusted; statuses=%v", codes(r))
	}
	if r.Valid {
		t.Errorf("expected Valid=false against production trust list")
	}
}

// TestValidate_TamperedSignature flips a byte inside the COSE signature box so
// the signature no longer verifies.
func TestValidate_TamperedSignature(t *testing.T) {
	pool, data := fixtureSigningPool(t)
	// Locate the signature box bytes and flip a byte near its end (the COSE
	// signature value sits late in the box).
	jumbf := extractJUMBF(context.Background(), JPEG, data)
	m := parseStore(context.Background(), jumbf).active()
	if len(m.signature) == 0 {
		t.Fatal("no signature")
	}
	idx := bytes.Index(data, m.signature)
	if idx < 0 {
		t.Fatal("signature bytes not found in file")
	}
	tampered := append([]byte(nil), data...)
	tampered[idx+len(m.signature)-4] ^= 0xFF

	r := Validate(context.Background(), JPEG, bytes.NewReader(tampered), WithSigningTrust(pool))
	if !r.Has(StatusClaimSignatureMismatch) {
		t.Errorf("expected claimSignature.mismatch; statuses=%v", codes(r))
	}
	if r.Valid {
		t.Errorf("expected Valid=false for tampered signature")
	}
}

// TestValidate_FullValid validates the fixture end-to-end (signature, chain,
// assertion hashes, hard binding) against its own trust anchor and expects a
// clean Valid=true with the hash-binding success codes present.
func TestValidate_FullValid(t *testing.T) {
	pool, data := fixtureSigningPool(t)
	tsaPool := fixtureTimestampPool(t)
	r := Validate(context.Background(), JPEG, bytes.NewReader(data),
		WithSigningTrust(pool), WithTimestampTrust(tsaPool))
	if !r.Valid {
		t.Errorf("expected Valid=true; first failure=%+v; statuses=%v", r.FirstFailure(), codes(r))
	}
	for _, want := range []StatusCode{
		StatusClaimSignatureValidated, StatusSigningCredentialTrusted,
		StatusTimeStampValidated,
		StatusAssertionHashedURIMatch, StatusAssertionDataHashMatch,
	} {
		if !r.Has(want) {
			t.Errorf("missing expected status %q; got %v", want, codes(r))
		}
	}
}

// TestValidate_TamperedDataHash flips an image-data byte outside the manifest
// exclusion range so the hard-binding data hash no longer matches.
func TestValidate_TamperedDataHash(t *testing.T) {
	pool, data := fixtureSigningPool(t)
	// Exclusion covers [20,117293); bytes past it are image data.
	tampered := append([]byte(nil), data...)
	tampered[160000] ^= 0xFF
	r := Validate(context.Background(), JPEG, bytes.NewReader(tampered), WithSigningTrust(pool))
	if !r.Has(StatusAssertionDataHashMismatch) {
		t.Errorf("expected assertion.dataHash.mismatch; got %v", codes(r))
	}
	if r.Valid {
		t.Error("expected Valid=false for tampered image data")
	}
}

// TestValidate_TamperedAssertion flips a byte inside an assertion box (within
// the excluded manifest region, so the data hash still matches) so its
// hashed_uri no longer matches the claim.
func TestValidate_TamperedAssertion(t *testing.T) {
	pool, data := fixtureSigningPool(t)
	jumbf := extractJUMBF(context.Background(), JPEG, data)
	m := parseStore(context.Background(), jumbf).active()

	// Find an assertion whose box content appears contiguously in the file.
	idx, blen := -1, 0
	for _, a := range m.assertions {
		if i := bytes.Index(data, a.boxContent); i >= 0 {
			idx, blen = i, len(a.boxContent)
			break
		}
	}
	if idx < 0 {
		t.Skip("no assertion box found contiguously in file (spans APP11 segments)")
	}
	tampered := append([]byte(nil), data...)
	tampered[idx+blen/2] ^= 0xFF
	r := Validate(context.Background(), JPEG, bytes.NewReader(tampered), WithSigningTrust(pool))
	if !r.Has(StatusAssertionHashedURIMismatch) {
		t.Errorf("expected assertion.hashedURI.mismatch; got %v", codes(r))
	}
	if r.Valid {
		t.Error("expected Valid=false for tampered assertion")
	}
}

func codes(r ValidationResult) []StatusCode {
	out := make([]StatusCode, 0, len(r.Statuses))
	for _, s := range r.Statuses {
		out = append(out, s.Code)
	}
	return out
}
