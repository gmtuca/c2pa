package c2pa

import (
	"context"
	"encoding/base64"
	"encoding/xml"
	"strings"
)

const (
	// svgManifestNS is the namespace the c2pa:manifest element is bound to.
	svgManifestNS = "http://c2pa.org/manifest"
	// svgManifestLocal is the element's local name once the namespace is resolved.
	svgManifestLocal = "manifest"
	// maxSVGTokens bounds the XML walk over adversarial input.
	maxSVGTokens = 1 << 20
)

// svgJUMBF returns the raw JUMBF manifest store from an SVG, or nil when there
// is none.
//
// SVG is the one text carrier: the store is base64 inside a <c2pa:manifest>
// element bound to http://c2pa.org/manifest, nested in <metadata>. The document
// is parsed as XML rather than pattern-matched, so a matching string in a
// comment, a CDATA section or an attribute is not mistaken for the store.
//
// encoding/xml does not resolve external entities, so the classic XXE and
// billion-laughs expansions are not reachable here; the token walk is still
// bounded and honours ctx.
func svgJUMBF(ctx context.Context, data []byte) []byte {
	dec := xml.NewDecoder(strings.NewReader(string(data)))
	dec.Strict = false
	dec.AutoClose = xml.HTMLAutoClose

	for tokens := 0; tokens < maxSVGTokens; tokens++ {
		if ctx.Err() != nil {
			return nil
		}
		tok, err := dec.Token()
		if err != nil {
			return nil // io.EOF included: no manifest element found
		}
		start, ok := tok.(xml.StartElement)
		if !ok || start.Name.Local != svgManifestLocal || start.Name.Space != svgManifestNS {
			continue
		}
		var encoded string
		if err := dec.DecodeElement(&encoded, &start); err != nil {
			return nil
		}
		store, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(encoded), ""))
		if err != nil || len(store) == 0 {
			return nil
		}
		return store
	}
	return nil
}
