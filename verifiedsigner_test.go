package c2pa

import (
	"bytes"
	"context"
	"os"
	"testing"
)

// TestSignerChainIsTheActiveManifests pins the bug this file exists for.
// c2pa_signed_video.mp4's active manifest is signed by "C2PA Signer"; it embeds
// an ingredient manifest signed by "Bob" at Media Publisher Company. Because
// validateManifest recurses into ingredients AFTER assigning the result's
// signer, an unguarded assignment leaves Bob — the author of material that went
// into the video — reported as the signer of the video itself.
func TestSignerChainIsTheActiveManifests(t *testing.T) {
	data, err := os.ReadFile("testdata/c2pa_signed_video.mp4")
	if err != nil {
		t.Fatal(err)
	}
	r := Validate(context.Background(), BMFF, bytes.NewReader(data))
	if len(r.SignerChain) == 0 {
		t.Fatal("no signer chain parsed")
	}
	got := r.SignerChain[0].Subject.CommonName
	if got == "Bob" {
		t.Fatalf("SignerChain is the ingredient's signer (%q); it must be the active manifest's", got)
	}
	if got != "C2PA Signer" {
		t.Errorf("SignerChain[0] CN = %q, want the active manifest's signer %q", got, "C2PA Signer")
	}
}

// TestVerifiedSignerRequiresProof: the fixture's chain does not reach a trust
// anchor under the production trust list, so the identity is unproven and must
// not be reported, even though SignerChain is populated.
func TestVerifiedSignerRequiresProof(t *testing.T) {
	data, err := os.ReadFile("testdata/c2pa_signed.jpg")
	if err != nil {
		t.Fatal(err)
	}
	r := Validate(context.Background(), JPEG, bytes.NewReader(data))
	if !r.Has(StatusSigningCredentialUntrusted) {
		t.Skip("fixture now chains to a trusted anchor; this case no longer applies")
	}
	if len(r.SignerChain) == 0 {
		t.Fatal("expected the chain to be present but untrusted")
	}
	if got := r.VerifiedSigner(); got != "" {
		t.Errorf("VerifiedSigner = %q for an untrusted chain, want \"\"", got)
	}
}

// TestVerifiedSignerWhenTrusted anchors the fixture's own intermediate, the way
// the positive validation tests do, and expects the identity to be reported.
func TestVerifiedSignerWhenTrusted(t *testing.T) {
	pool, data := fixtureSigningPool(t)
	r := Validate(context.Background(), JPEG, bytes.NewReader(data), WithSigningTrust(pool))

	if !r.hasForActive(StatusSigningCredentialTrusted) {
		t.Fatalf("expected a trusted chain; first failure = %v", r.FirstFailure())
	}
	if got := r.VerifiedSigner(); got != "C2PA Signer" {
		t.Errorf("VerifiedSigner = %q, want %q", got, "C2PA Signer")
	}
}

// TestHasForActiveIgnoresIngredientStatuses is the reason VerifiedSigner does
// not use plain Has: a trusted ingredient must not vouch for an untrusted asset.
func TestHasForActiveIgnoresIngredientStatuses(t *testing.T) {
	r := ValidationResult{
		ActiveManifestLabel: "urn:uuid:active",
		Statuses: []StatusEntry{
			{Code: StatusSigningCredentialTrusted, URI: "urn:uuid:ingredient"},
			{Code: StatusSigningCredentialUntrusted, URI: "urn:uuid:active"},
		},
	}
	if !r.Has(StatusSigningCredentialTrusted) {
		t.Fatal("precondition: plain Has should match the ingredient's status")
	}
	if r.hasForActive(StatusSigningCredentialTrusted) {
		t.Error("hasForActive matched an ingredient's status against the active manifest")
	}
	if got := r.VerifiedSigner(); got != "" {
		t.Errorf("VerifiedSigner = %q; a trusted ingredient must not vouch for the asset", got)
	}
}
