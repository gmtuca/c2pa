package c2pa

import (
	"bytes"
	"compress/flate"
	"compress/zlib"
	"context"
	"encoding/binary"
	"io"
	"strconv"
)

// PDF container support: the manifest store sits in neither a marker segment
// nor a box of its own. Per C2PA spec §A.4.1 it is an embedded file stream
// (ISO 32000 §7.11.4) whose file specification carries /AFRelationship
// /C2PA_Manifest, and per §A.4.2.1 the document catalog's /AF array holds an
// indirect reference to the specification containing the active manifest. The
// stream payload is the raw JUMBF store.

// This is a lexical object scanner, not a full PDF parser: it indexes the
// `N G obj … endobj` definitions it can see, follows that chain when it
// resolves, and falls back to the spec's own markers when it does not — a
// catalog or file specification compressed into an object stream is invisible.
// A stream object may never live inside an object stream (PDF 32000-1 §7.5.7),
// so the store itself is always visible even when the pointers to it are not.

// Incremental updates append rather than rewrite, so §A.4.2.1 makes the store
// in the most recent update section the active manifest: here the last /Root
// names the current catalog and the last definition of an object number
// supersedes the ones before it. §A.4.2.1 also asks a consumer to process the
// stores of ALL update sections as one; that is not done — see the fallback in
// pdfMarkedStore for how a superseded store is still surfaced.

// The names §A.4.1 gives the C2PA embedded file. The /Subtype is accepted but
// never required: the spec puts it on the file specification dictionary while
// ISO 32000 defines it on the stream dictionary, and the official C2PA test PDF
// carries it on neither.
const (
	pdfC2PARelationship = "C2PA_Manifest"
	pdfC2PAMediaType    = "application/c2pa"
)

// maxPDFObjects caps the object index. Indexed bodies are subslices of the
// input, so the cost is the index itself; a file of nothing but `0 0 obj`
// markers would otherwise index one entry per 8 bytes of input.
const maxPDFObjects = 1 << 18

// maxPDFAssociatedFiles caps how many /AF entries are followed. Real documents
// attach a handful of associated files, one of them the C2PA manifest.
const maxPDFAssociatedFiles = 64

// maxPDFInflate is the decompression budget for one extraction, shared by every
// candidate stream, so neither a compression bomb in the /EF stream nor a file
// full of them can exhaust memory. A manifest store is orders of magnitude
// smaller than this even with embedded thumbnails.
const maxPDFInflate = MaxScan

// maxPDFHeaderSearch bounds the %PDF- header search. Readers tolerate leading
// junk before the header; requiring it somewhere near the front keeps the
// scanner off input that is not a PDF at all.
const maxPDFHeaderSearch = 1024

// maxPDFDictScan bounds how far into an object body a key lookup reads. The
// dictionary comes first and the ones these lookups care about run to a few
// hundred bytes; without a bound, a file of overlapping unterminated objects
// would cost a full scan per object.
const maxPDFDictScan = 2048

// maxPDFStoreAttempts caps how many candidate streams are decoded before the
// marker scan gives up, so a file that repeats a marker cannot make it inflate
// the rest of the file once per copy.
const maxPDFStoreAttempts = 32

// pdfObject is one `N G obj … endobj` definition. body is a subslice of the
// asset bytes running from just past the `obj` keyword to `endobj`, so a
// stream's payload stays addressable.
type pdfObject struct {
	num  int
	body []byte
}

// pdfObjects is the indexed object graph: every definition in file order, plus
// a lookup that resolves an object number to its newest definition.
type pdfObjects struct {
	order   []pdfObject
	newest  map[int]int // object number → index into order
	inflate int         // decompression budget left for this extraction
}

// body returns the newest definition of an object number, or nil when the
// object is not visible (typically because it lives in an object stream).
func (o *pdfObjects) body(num int) []byte {
	if i, ok := o.newest[num]; ok {
		return o.order[i].body
	}
	return nil
}

// pdfJUMBF locates the C2PA manifest store in a PDF and returns its raw JUMBF
// bytes. Returns nil when the document carries none.
func pdfJUMBF(ctx context.Context, data []byte) []byte {
	if !bytes.Contains(data[:min(len(data), maxPDFHeaderSearch)], []byte("%PDF-")) {
		return nil
	}
	objs := indexPDFObjects(ctx, data)
	if len(objs.order) == 0 {
		return nil
	}
	if store := pdfActiveStore(ctx, data, objs); store != nil {
		return store
	}
	return pdfMarkedStore(ctx, objs)
}

// indexPDFObjects indexes every visible indirect object definition. A later
// definition of the same object number supersedes an earlier one: that is what
// an incremental update is.
func indexPDFObjects(ctx context.Context, data []byte) *pdfObjects {
	objs := &pdfObjects{newest: map[int]int{}, inflate: maxPDFInflate}
	// endobj advances monotonically: once we know where the next `endobj` is,
	// or that there is none, later headers reuse it. Re-searching per header
	// would cost a full scan each for a file of unterminated objects.
	endobj := -1
	for i := 0; i < len(data) && len(objs.order) < maxPDFObjects; {
		if ctx.Err() != nil {
			return objs
		}
		k := bytes.Index(data[i:], []byte("obj"))
		if k < 0 {
			break
		}
		pos := i + k
		i = pos + len("obj")
		num, ok := pdfObjNumber(data, pos)
		if !ok {
			continue
		}
		if endobj < i {
			if e := bytes.Index(data[i:], []byte("endobj")); e >= 0 {
				endobj = i + e
			} else {
				endobj = len(data)
			}
		}
		objs.newest[num] = len(objs.order)
		objs.order = append(objs.order, pdfObject{num: num, body: data[i:endobj]})
	}
	return objs
}

// pdfObjNumber parses the `N G obj` header whose `obj` keyword starts at pos.
// It insists on the whole token shape — digits, space, digits, space, `obj`,
// delimiter — so neither the `obj` inside `endobj` nor a chance occurrence in
// stream bytes indexes a phantom object.
func pdfObjNumber(data []byte, pos int) (int, bool) {
	if p := pos + len("obj"); p < len(data) && !pdfIsSpace(data[p]) && !pdfIsDelim(data[p]) {
		return 0, false
	}
	i := pdfSkipSpaceBack(data, pos)
	if i == pos {
		return 0, false
	}
	_, i, ok := pdfUintBack(data, i) // generation number
	if !ok {
		return 0, false
	}
	j := pdfSkipSpaceBack(data, i)
	if j == i {
		return 0, false
	}
	num, j, ok := pdfUintBack(data, j)
	if !ok {
		return 0, false
	}
	if j > 0 && !pdfIsSpace(data[j-1]) && !pdfIsDelim(data[j-1]) {
		return 0, false
	}
	return num, true
}

// pdfActiveStore returns the active manifest by the route §A.4.2.1 defines: the
// current trailer's /Root names the document catalog, whose /AF array lists the
// associated files, and the one whose /AFRelationship is /C2PA_Manifest carries
// the store in its /EF stream. Returns nil when that chain does not resolve —
// no /Root, or a catalog or file specification compressed into an object
// stream.
func pdfActiveStore(ctx context.Context, data []byte, objs *pdfObjects) []byte {
	root, ok := pdfRootRef(data)
	if !ok {
		return nil
	}
	catalog := objs.body(root)
	if catalog == nil {
		return nil
	}
	refs := pdfRefs(catalog, "AF", maxPDFAssociatedFiles)
	if len(refs) == 1 {
		// /AF may be an indirect reference to the array rather than the array.
		if b := objs.body(refs[0]); pdfPeek(b) == '[' {
			refs = pdfRefList(b, maxPDFAssociatedFiles)
		}
	}
	for _, ref := range refs {
		if ctx.Err() != nil {
			return nil
		}
		filespec := objs.body(ref)
		if filespec == nil || pdfName(pdfDict(filespec), "AFRelationship") != pdfC2PARelationship {
			continue
		}
		if store := pdfEmbeddedStore(ctx, objs, filespec); store != nil {
			return store
		}
	}
	return nil
}

// pdfMarkedStore scans the visible objects, newest first, for a C2PA embedded
// file by the markers §A.4.1 puts on it: a file specification carrying the
// /C2PA_Manifest relationship, or failing that a stream declaring the C2PA
// media type as its /Subtype. It picks up a document whose pointer chain is
// compressed out of sight, and a store from an earlier update section that the
// current catalog no longer associates — §15.5.2.2 keeps those valid.
func pdfMarkedStore(ctx context.Context, objs *pdfObjects) []byte {
	// A store found this way may equally be an object-level manifest (§A.4.3),
	// which describes an embedded image or font rather than the document; the
	// markers are the same and nothing distinguishes them here.
	attempts := 0
	for _, marker := range []struct{ key, want string }{
		{"AFRelationship", pdfC2PARelationship},
		{"Subtype", pdfC2PAMediaType},
	} {
		for i := len(objs.order) - 1; i >= 0 && attempts < maxPDFStoreAttempts; i-- {
			if ctx.Err() != nil {
				return nil
			}
			body := objs.order[i].body
			if pdfText(pdfDict(body), marker.key) != marker.want {
				continue
			}
			attempts++
			if store := pdfEmbeddedStore(ctx, objs, body); store != nil {
				return store
			}
		}
	}
	return nil
}

// pdfStoreCount counts the distinct embedded-file streams that a C2PA file
// specification points at. More than one means the document carries stores this
// extractor does not evaluate: earlier update sections' stores, which
// §A.4.2.1 asks a consumer to process together with the active one, or
// object-level manifests (§A.4.3).
func pdfStoreCount(ctx context.Context, data []byte) int {
	seen := map[int]bool{}
	for _, o := range indexPDFObjects(ctx, data).order {
		if ctx.Err() != nil {
			return len(seen)
		}
		if pdfName(pdfDict(o.body), "AFRelationship") != pdfC2PARelationship {
			continue
		}
		if num, ok := pdfEmbeddedFileRef(o.body); ok {
			seen[num] = true
		}
	}
	return len(seen)
}

// pdfEmbeddedStore resolves a file specification to its embedded-file stream
// and returns the JUMBF store inside it. The relationship and media type also
// appear on the stream object itself in some producers' output, so a body that
// has no /EF is retried as the stream.
func pdfEmbeddedStore(ctx context.Context, objs *pdfObjects, filespec []byte) []byte {
	if num, ok := pdfEmbeddedFileRef(filespec); ok {
		if store := objs.streamStore(ctx, objs.body(num)); store != nil {
			return store
		}
	}
	return objs.streamStore(ctx, filespec)
}

// pdfEmbeddedFileRef returns the object number of a file specification's
// embedded-file stream: the /EF dictionary's /F entry, falling back to the
// Unicode and platform-specific keys.
func pdfEmbeddedFileRef(filespec []byte) (int, bool) {
	dict := pdfDict(filespec)
	p := pdfFindName(dict, "EF", 0)
	if p < 0 {
		return 0, false
	}
	for _, key := range []string{"F", "UF", "DOS", "Mac", "Unix"} {
		if refs := pdfRefs(dict[p:], key, 1); len(refs) == 1 {
			return refs[0], true
		}
	}
	return 0, false
}

// streamStore decodes an object's stream and returns the JUMBF manifest store
// it holds, trimmed to the superbox's own length (the stream may be padded).
// Returns nil unless the decoded bytes really are a JUMBF superbox, which is
// what keeps a lexical mis-hit harmless.
func (o *pdfObjects) streamStore(ctx context.Context, body []byte) []byte {
	if ctx.Err() != nil || len(body) == 0 {
		return nil
	}
	dict, raw := pdfStreamPayload(body)
	if len(raw) == 0 {
		return nil
	}
	store := o.decodeStream(dict, raw)
	if !looksLikeJUMBF(store, 0, len(store)) {
		return nil
	}
	return store[:binary.BigEndian.Uint32(store[:4])]
}

// pdfStreamPayload returns the still-encoded bytes between an object's `stream`
// keyword and its `endstream`. /Length is a hint, verified before use and never
// trusted — it may be an indirect reference, and a length that lies must not
// slice past the object — so the keyword search is what bounds the payload.
// Trailing bytes are left on: the decoders stop at the end of their own stream,
// and an uncompressed store is trimmed by its superbox length.
func pdfStreamPayload(body []byte) (dict, payload []byte) {
	for pos := 0; pos < len(body); {
		k := bytes.Index(body[pos:], []byte("stream"))
		if k < 0 {
			return nil, nil
		}
		start := pos + k
		pos = start + len("stream")
		if start > 0 && !pdfIsSpace(body[start-1]) && !pdfIsDelim(body[start-1]) {
			continue // part of a longer token, e.g. `endstream`
		}
		dict, p := body[:start], pos
		// The spec requires CRLF or LF (not a bare CR) after the keyword.
		if p >= len(body) || (body[p] != '\r' && body[p] != '\n') {
			continue
		}
		if body[p] == '\r' {
			p++
		}
		if p < len(body) && body[p] == '\n' {
			p++
		}
		if n, ok := pdfInt(dict, "Length"); ok && n >= 0 && p+n <= len(body) &&
			bytes.HasPrefix(bytes.TrimLeft(body[p+n:], "\x00\t\n\f\r "), []byte("endstream")) {
			return dict, body[p : p+n]
		}
		e := bytes.Index(body[p:], []byte("endstream"))
		if e < 0 {
			return nil, nil
		}
		return dict, body[p : p+e]
	}
	return nil, nil
}

// decodeStream applies the stream's /Filter. The spec says nothing about
// filters on this stream — §A.4.1 covers only encryption, where the crypt
// filter must be Identity, hence the /Crypt pass-through — so both an
// unfiltered store and a /FlateDecode one are read. Any other filter is left
// undecoded: the caller then sees non-JUMBF bytes and reports no manifest
// rather than guessing.
func (o *pdfObjects) decodeStream(dict, raw []byte) []byte {
	filters := pdfNames(dict, "Filter", 3)
	if len(filters) > 0 && filters[0] == "Crypt" {
		filters = filters[1:]
	}
	switch {
	case len(filters) == 0:
		return raw
	case len(filters) == 1 && (filters[0] == "FlateDecode" || filters[0] == "Fl"):
		out := pdfInflate(raw, o.inflate)
		o.inflate -= len(out)
		return out
	default:
		return nil
	}
}

// pdfInflate decompresses a /FlateDecode stream, up to limit bytes. PDF's
// FlateDecode is zlib-wrapped; a raw deflate payload (which some producers
// emit) is retried without the wrapper. Whatever decoded before an error is
// kept, so a truncated stream still yields the store when the store came first.
func pdfInflate(raw []byte, limit int) []byte {
	if limit <= 0 {
		return nil
	}
	if zr, err := zlib.NewReader(bytes.NewReader(raw)); err == nil {
		out := pdfDrain(zr, limit)
		_ = zr.Close()
		if len(out) > 0 {
			return out
		}
	}
	fr := flate.NewReader(bytes.NewReader(raw))
	out := pdfDrain(fr, limit)
	_ = fr.Close()
	return out
}

func pdfDrain(r io.Reader, limit int) []byte {
	out, _ := io.ReadAll(io.LimitReader(r, int64(limit)))
	return out
}

// pdfRootRef returns the object number of the document catalog, taken from the
// last /Root in the file. Both a classic `trailer` dictionary and an xref
// stream's dictionary spell it out in plain bytes, and an incremental update
// appends a fresh one, so the final occurrence names the current catalog.
func pdfRootRef(data []byte) (int, bool) {
	root, found := 0, false
	for i := 0; i < len(data); {
		p := pdfFindName(data, "Root", i)
		if p < 0 {
			break
		}
		i = p
		if refs := pdfRefList(data[p:], 1); len(refs) == 1 {
			root, found = refs[0], true
		}
	}
	return root, found
}

// pdfDict returns the leading window of an object body that a key lookup reads:
// the dictionary, which precedes any stream payload.
func pdfDict(body []byte) []byte {
	return body[:min(len(body), maxPDFDictScan)]
}

// pdfFindName returns the offset just past the name token /key in b, at or
// after from, or -1. The token must end at a delimiter, so a lookup of /AF does
// not match /AFRelationship. The search is lexical — a nested dictionary using
// the same name can shadow the outer one — but every offset it yields is
// length-checked and the result must still parse as a JUMBF store, so a wrong
// hit costs a nil return rather than a bad read.
func pdfFindName(b []byte, key string, from int) int {
	tok := "/" + key
	for i := from; i >= 0 && i < len(b); {
		k := bytes.Index(b[i:], []byte(tok))
		if k < 0 {
			return -1
		}
		e := i + k + len(tok)
		if e >= len(b) || pdfIsSpace(b[e]) || pdfIsDelim(b[e]) {
			return e
		}
		i = e
	}
	return -1
}

// pdfNames reads the value of /key as name objects, accepting both a bare name
// (/FlateDecode) and an array of them ([/FlateDecode]), with #XX escapes
// resolved and the leading slash dropped.
func pdfNames(b []byte, key string, max int) []string {
	p := pdfFindName(b, key, 0)
	if p < 0 {
		return nil
	}
	p, end := pdfSkipSpace(b, p), len(b)
	if p < end && b[p] == '[' {
		p++
		if e := bytes.IndexByte(b[p:], ']'); e >= 0 {
			end = p + e
		}
	} else {
		max = 1 // a bare value is one name; the next one belongs to another key
	}
	var out []string
	for len(out) < max {
		p = pdfSkipSpace(b, p)
		if p >= end || b[p] != '/' {
			break
		}
		p++
		s := p
		for p < end && !pdfIsSpace(b[p]) && !pdfIsDelim(b[p]) {
			p++
		}
		out = append(out, pdfUnescapeName(b[s:p]))
	}
	return out
}

// pdfName reads /key as a single name object, "" when absent or not a name.
func pdfName(b []byte, key string) string {
	if names := pdfNames(b, key, 1); len(names) == 1 {
		return names[0]
	}
	return ""
}

// pdfText reads /key as either a name (/application#2Fc2pa) or a literal string
// ((application/c2pa)). The C2PA /Subtype is a media type and the spec never
// shows which of the two a producer writes it as.
func pdfText(b []byte, key string) string {
	p := pdfFindName(b, key, 0)
	if p < 0 {
		return ""
	}
	if p = pdfSkipSpace(b, p); p < len(b) && b[p] == '(' {
		if e := bytes.IndexByte(b[p:], ')'); e > 0 {
			return string(b[p+1 : p+e])
		}
		return ""
	}
	return pdfName(b, key)
}

// pdfUnescapeName resolves a PDF name's #XX hex escapes, which is how the C2PA
// media type's slash is written: `application#2Fc2pa`.
func pdfUnescapeName(b []byte) string {
	if !bytes.ContainsRune(b, '#') {
		return string(b)
	}
	out := make([]byte, 0, len(b))
	for i := 0; i < len(b); i++ {
		if b[i] == '#' && i+2 < len(b) {
			hi, okHi := pdfHexDigit(b[i+1])
			lo, okLo := pdfHexDigit(b[i+2])
			if okHi && okLo {
				out = append(out, hi<<4|lo)
				i += 2
				continue
			}
		}
		out = append(out, b[i])
	}
	return string(out)
}

// pdfInt reads /key as a direct integer. An indirect reference (`/Length 9 0 R`)
// reports absent rather than its object number, so a caller cannot read 9 as the
// value; the callers all have a fallback for absent.
func pdfInt(b []byte, key string) (int, bool) {
	p := pdfFindName(b, key, 0)
	if p < 0 {
		return 0, false
	}
	if _, _, ok := pdfRefAt(b, p, len(b)); ok {
		return 0, false
	}
	v, _, ok := pdfUint(b, pdfSkipSpace(b, p), len(b))
	return v, ok
}

// pdfRefs collects the indirect references in the value of /key, capped at max.
func pdfRefs(b []byte, key string, max int) []int {
	p := pdfFindName(b, key, 0)
	if p < 0 {
		return nil
	}
	return pdfRefList(b[p:], max)
}

// pdfRefList parses indirect references (`N G R`) from the start of b, stepping
// into a leading array. It stops at the first token that is not a reference.
func pdfRefList(b []byte, max int) []int {
	p, end := pdfSkipSpace(b, 0), len(b)
	if p < end && b[p] == '[' {
		p++
		if e := bytes.IndexByte(b[p:], ']'); e >= 0 {
			end = p + e
		}
	} else {
		max = 1 // a bare value is one reference, not the start of a run
	}
	var out []int
	for len(out) < max {
		num, next, ok := pdfRefAt(b, p, end)
		if !ok {
			break
		}
		out = append(out, num)
		p = next
	}
	return out
}

// pdfRefAt parses one `N G R` indirect reference in b[p:end].
func pdfRefAt(b []byte, p, end int) (num, next int, ok bool) {
	p = pdfSkipSpace(b, p)
	num, p, ok = pdfUint(b, p, end)
	if !ok {
		return 0, 0, false
	}
	q := pdfSkipSpace(b, p)
	if q == p {
		return 0, 0, false
	}
	if _, p, ok = pdfUint(b, q, end); !ok {
		return 0, 0, false
	}
	q = pdfSkipSpace(b, p)
	if q == p || q >= end || b[q] != 'R' {
		return 0, 0, false
	}
	return num, q + 1, true
}

// pdfUint reads decimal digits at b[p:end], returning the value and the offset
// past them. The digit run is capped so the accumulator cannot overflow.
func pdfUint(b []byte, p, end int) (int, int, bool) {
	if end > len(b) {
		end = len(b)
	}
	i := p
	for i < end && b[i] >= '0' && b[i] <= '9' && i-p < 10 {
		i++
	}
	if i == p {
		return 0, p, false
	}
	v, err := strconv.Atoi(string(b[p:i]))
	if err != nil {
		return 0, p, false
	}
	return v, i, true
}

// pdfUintBack reads decimal digits backwards from b[i-1], returning the value
// and the offset of its first digit. Capped like pdfUint.
func pdfUintBack(b []byte, i int) (int, int, bool) {
	end := i
	for i > 0 && b[i-1] >= '0' && b[i-1] <= '9' && end-i < 10 {
		i--
	}
	if i == end {
		return 0, i, false
	}
	v, err := strconv.Atoi(string(b[i:end]))
	if err != nil {
		return 0, i, false
	}
	return v, i, true
}

func pdfSkipSpace(b []byte, i int) int {
	for i < len(b) && pdfIsSpace(b[i]) {
		i++
	}
	return i
}

func pdfSkipSpaceBack(b []byte, i int) int {
	for i > 0 && pdfIsSpace(b[i-1]) {
		i--
	}
	return i
}

// pdfPeek returns the first non-whitespace byte of b, or 0 when there is none.
func pdfPeek(b []byte) byte {
	if i := pdfSkipSpace(b, 0); i < len(b) {
		return b[i]
	}
	return 0
}

// pdfIsSpace reports the six PDF whitespace characters (32000-1 §7.2.2).
func pdfIsSpace(c byte) bool {
	return c == 0x00 || c == '\t' || c == '\n' || c == '\f' || c == '\r' || c == ' '
}

// pdfIsDelim reports the PDF delimiter characters (32000-1 §7.2.2).
func pdfIsDelim(c byte) bool {
	switch c {
	case '(', ')', '<', '>', '[', ']', '{', '}', '/', '%':
		return true
	}
	return false
}

func pdfHexDigit(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}
