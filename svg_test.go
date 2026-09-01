package c2pa

import (
	"bytes"
	"context"
	"encoding/base64"
	"testing"
)

func svgWith(inner string) []byte {
	return []byte(`<svg xmlns="http://www.w3.org/2000/svg" xmlns:c2pa="` + svgManifestNS + `">` +
		inner + `<rect width="1" height="1"/></svg>`)
}

func svgWithStore(store []byte) []byte {
	return svgWith(`<metadata><c2pa:manifest>` +
		base64.StdEncoding.EncodeToString(store) + `</c2pa:manifest></metadata>`)
}

func TestSVGJUMBF_Found(t *testing.T) {
	store := []byte("\x00\x00\x00\x10jumbthe-store-here")
	if got := svgJUMBF(context.Background(), svgWithStore(store)); !bytes.Equal(got, store) {
		t.Errorf("got %q, want %q", got, store)
	}
}

// TestSVGJUMBF_WhitespaceInBase64 covers pretty-printed SVG, where the encoded
// store is wrapped across lines and indented.
func TestSVGJUMBF_WhitespaceInBase64(t *testing.T) {
	store := bytes.Repeat([]byte("provenance"), 20)
	encoded := base64.StdEncoding.EncodeToString(store)
	var wrapped string
	for i := 0; i < len(encoded); i += 40 {
		wrapped += "\n      " + encoded[i:min(i+40, len(encoded))]
	}
	data := svgWith(`<metadata><c2pa:manifest>` + wrapped + "\n    </c2pa:manifest></metadata>")

	if got := svgJUMBF(context.Background(), data); !bytes.Equal(got, store) {
		t.Errorf("wrapped base64 did not round-trip: got %d bytes, want %d", len(got), len(store))
	}
}

// TestSVGJUMBF_NamespaceIsWhatMatters: an element merely named c2pa:manifest,
// bound to some other namespace, is not the manifest.
func TestSVGJUMBF_NamespaceIsWhatMatters(t *testing.T) {
	encoded := base64.StdEncoding.EncodeToString([]byte("impostor"))
	data := []byte(`<svg xmlns="http://www.w3.org/2000/svg" xmlns:c2pa="http://example.com/not-c2pa">` +
		`<metadata><c2pa:manifest>` + encoded + `</c2pa:manifest></metadata></svg>`)

	if got := svgJUMBF(context.Background(), data); got != nil {
		t.Errorf("a foreign namespace must not match, got %q", got)
	}
}

// TestSVGJUMBF_MarkerInTextIsNotAStore is why this parses XML instead of
// pattern-matching: the same text in a comment or a CDATA section is content.
func TestSVGJUMBF_MarkerInTextIsNotAStore(t *testing.T) {
	encoded := base64.StdEncoding.EncodeToString([]byte("decoy store"))
	for _, inner := range []string{
		`<!-- <c2pa:manifest>` + encoded + `</c2pa:manifest> -->`,
		`<desc><![CDATA[<c2pa:manifest>` + encoded + `</c2pa:manifest>]]></desc>`,
		`<desc>&lt;c2pa:manifest&gt;` + encoded + `&lt;/c2pa:manifest&gt;</desc>`,
	} {
		if got := svgJUMBF(context.Background(), svgWith(inner)); got != nil {
			t.Errorf("inner %.40s…: got %q, want nil", inner, got)
		}
	}
}

func TestSVGJUMBF_Absent(t *testing.T) {
	if got := svgJUMBF(context.Background(), svgWith(`<title>no provenance</title>`)); got != nil {
		t.Errorf("got %q, want nil", got)
	}
}

func TestSVGJUMBF_NotXML(t *testing.T) {
	for _, in := range [][]byte{nil, []byte("not xml at all"), []byte("<svg"), []byte("\xff\xd8\xff\xe0")} {
		if got := svgJUMBF(context.Background(), in); got != nil {
			t.Errorf("input %q: got %q, want nil", in, got)
		}
	}
}

func TestSVGJUMBF_BadBase64(t *testing.T) {
	data := svgWith(`<metadata><c2pa:manifest>!!! not base64 !!!</c2pa:manifest></metadata>`)
	if got := svgJUMBF(context.Background(), data); got != nil {
		t.Errorf("undecodable content must yield nil, got %q", got)
	}
}

func TestSVGJUMBF_EveryTruncation(t *testing.T) {
	store := []byte("\x00\x00\x00\x08jumbpayload")
	full := svgWithStore(store)

	for n := range len(full) {
		if got := svgJUMBF(context.Background(), full[:n]); got != nil && !bytes.Equal(got, store) {
			t.Fatalf("truncation at %d produced a store that is not the real one: %q", n, got)
		}
	}
	if got := svgJUMBF(context.Background(), full); !bytes.Equal(got, store) {
		t.Fatalf("the untruncated file must still yield the store, got %q", got)
	}
}

func TestSVGJUMBF_CancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if got := svgJUMBF(ctx, svgWithStore([]byte("store"))); got != nil {
		t.Errorf("cancelled context must yield nil, got %q", got)
	}
}

func FuzzSVGParse(f *testing.F) {
	f.Add(svgWithStore([]byte("\x00\x00\x00\x08jumb")))
	f.Add(svgWith(`<title>plain</title>`))
	f.Add([]byte(`<svg xmlns:c2pa="` + svgManifestNS + `"><c2pa:manifest>####</c2pa:manifest></svg>`))
	f.Add([]byte("<!DOCTYPE svg [<!ENTITY a 'b'>]><svg>&a;</svg>"))

	f.Fuzz(func(t *testing.T, data []byte) {
		store := svgJUMBF(context.Background(), data)
		if store == nil {
			return
		}
		// base64 shrinks by a quarter, so a decoded store can never exceed the
		// document that carried it.
		if len(store) > len(data) {
			t.Fatalf("returned %d bytes from a %d-byte input", len(store), len(data))
		}
	})
}
