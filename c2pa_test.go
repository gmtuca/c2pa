package c2pa

import (
	"bytes"
	"context"
	"os"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
)

// TestRead_SignedJPEG parses the JUMBF manifest from a real C2PA-signed JPEG
// (contentauth/c2pa-rs test fixture; see testdata/README.md).
func TestRead_SignedJPEG(t *testing.T) {
	f, err := os.Open("testdata/c2pa_signed.jpg")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()

	c := Read(context.Background(), JPEG, f)
	if !c.Present {
		t.Fatal("expected a C2PA manifest")
	}
	if !bytes.Contains([]byte(c.ClaimGenerator), []byte("c2pa-rs")) {
		t.Errorf("ClaimGenerator=%q want it to mention c2pa-rs", c.ClaimGenerator)
	}
	if c.Title != "CA.jpg" {
		t.Errorf("Title=%q want CA.jpg", c.Title)
	}
	if c.AIGenerated {
		t.Errorf("CA.jpg is edited, not AI-generated; want AIGenerated=false")
	}
	// Signer identity + signing time from the COSE_Sign1 envelope.
	if c.SignedBy != "C2PA Signer" {
		t.Errorf("SignedBy=%q want %q", c.SignedBy, "C2PA Signer")
	}
	wantSignedAt := time.Date(2024, 8, 6, 21, 53, 37, 0, time.UTC)
	if !c.SignedAt.Equal(wantSignedAt) {
		t.Errorf("SignedAt=%s want %s", c.SignedAt.Format(time.RFC3339), wantSignedAt.Format(time.RFC3339))
	}
}

// TestRead_NoManifest returns Present=false for content with no manifest.
func TestRead_NoManifest(t *testing.T) {
	if c := Read(context.Background(), JPEG, bytes.NewReader([]byte("\xff\xd8\xff\xe0 not a real manifest"))); c.Present {
		t.Errorf("expected no manifest, got %+v", c)
	}
}

// TestRead_UnknownContainer returns a zero Info for an unrecognised container.
func TestRead_UnknownContainer(t *testing.T) {
	if c := Read(context.Background(), Container("tiff"), bytes.NewReader([]byte("whatever"))); c.Present {
		t.Errorf("unknown container should yield no manifest, got %+v", c)
	}
}

// TestRead_Cancellation pins that a cancelled context is honoured by the scan,
// not run to completion: a pre-cancelled ctx bails at entry and parses nothing.
func TestRead_Cancellation(t *testing.T) {
	f, err := os.Open("testdata/c2pa_signed.jpg")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if c := Read(ctx, JPEG, f); c.Present {
		t.Errorf("cancelled ctx should yield no manifest, got %+v", c)
	}
}

// TestActionsAreAI checks the AI-generated detection on synthetic c2pa.actions
// assertions (no public AI-positive fixture available).
func TestActionsAreAI(t *testing.T) {
	ai := mustCBOR(t, map[string]any{"actions": []any{
		map[string]any{"action": "c2pa.created",
			"digitalSourceType": "http://cv.iptc.org/newscodes/digitalsourcetype/trainedAlgorithmicMedia"},
	}})
	aiParam := mustCBOR(t, map[string]any{"actions": []any{
		map[string]any{"action": "c2pa.created",
			"parameters": map[string]any{"digitalSourceType": "...compositeWithTrainedAlgorithmicMedia"}},
	}})
	notAI := mustCBOR(t, map[string]any{"actions": []any{
		map[string]any{"action": "c2pa.color_adjustments"},
		map[string]any{"action": "c2pa.opened"},
	}})

	for _, tc := range []struct {
		name string
		cbor []byte
		want bool
	}{
		{"top-level digitalSourceType", ai, true},
		{"parameters digitalSourceType", aiParam, true},
		{"edit-only actions", notAI, false},
	} {
		var m map[string]any
		if err := decMode.Unmarshal(tc.cbor, &m); err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if got := actionsAreAI(m); got != tc.want {
			t.Errorf("%s: actionsAreAI=%v want %v", tc.name, got, tc.want)
		}
	}
}

func mustCBOR(t *testing.T, v any) []byte {
	t.Helper()
	b, err := cbor.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
