package c2pa

import (
	"bytes"
	"context"
	"testing"
)

// gifFile frames a GIF89a with no global colour table followed by blocks.
func gifFile(blocks ...[]byte) []byte {
	out := append([]byte("GIF89a"), 1, 0, 1, 0, 0, 0, 0)
	for _, b := range blocks {
		out = append(out, b...)
	}
	return append(out, gifTrailer)
}

func gifC2PAExtension(store []byte) []byte {
	out := []byte{gifExtensionIntroducer, gifApplicationLabel, byte(len(gifC2PAIdentifier))}
	out = append(out, gifC2PAIdentifier...)
	return append(out, gifSubBlockChain(store)...)
}

// gifOtherExtension is a non-C2PA application extension, e.g. NETSCAPE looping.
func gifOtherExtension(id string, payload []byte) []byte {
	out := []byte{gifExtensionIntroducer, gifApplicationLabel, byte(len(id))}
	out = append(out, id...)
	return append(out, gifSubBlockChain(payload)...)
}

// gifImage is a minimal image descriptor with no local colour table.
func gifImage(lzw []byte) []byte {
	out := []byte{gifImageDescriptor, 0, 0, 0, 0, 1, 0, 1, 0, 0, 2}
	return append(out, gifSubBlockChain(lzw)...)
}

func TestGIFJUMBF_Found(t *testing.T) {
	store := []byte("\x00\x00\x00\x10jumbthe-store-here")
	data := gifFile(
		gifOtherExtension("NETSCAPE", []byte{1, 0, 0}),
		gifC2PAExtension(store),
		gifImage([]byte{0x44, 0x01}),
	)
	if got := gifJUMBF(context.Background(), data); !bytes.Equal(got, store) {
		t.Errorf("got %q, want %q", got, store)
	}
}

// TestGIFJUMBF_ReassemblesAcrossSubBlocks is the whole point of the sub-block
// chain: a store over 255 bytes cannot be a single slice.
func TestGIFJUMBF_ReassemblesAcrossSubBlocks(t *testing.T) {
	store := bytes.Repeat([]byte("abcdefgh"), 200) // 1600 bytes, 7 sub-blocks
	data := gifFile(gifC2PAExtension(store))
	got := gifJUMBF(context.Background(), data)
	if !bytes.Equal(got, store) {
		t.Errorf("reassembled %d bytes, want %d", len(got), len(store))
	}
}

func TestGIFJUMBF_GlobalColourTableIsSkipped(t *testing.T) {
	store := []byte("after the palette")
	// Packed byte 0x80|0x02 => a global colour table of 3 * 2^3 = 24 bytes.
	out := append([]byte("GIF89a"), 1, 0, 1, 0, 0x82, 0, 0)
	out = append(out, bytes.Repeat([]byte{0xAB}, 24)...)
	out = append(out, gifC2PAExtension(store)...)
	out = append(out, gifTrailer)

	if got := gifJUMBF(context.Background(), out); !bytes.Equal(got, store) {
		t.Errorf("got %q, want %q — the colour table was probably not skipped", got, store)
	}
}

// TestGIFJUMBF_MarkerInsideImageDataIsNotAStore is why the blocks are walked
// rather than scanned: LZW bytes can spell the identifier.
func TestGIFJUMBF_MarkerInsideImageDataIsNotAStore(t *testing.T) {
	decoy := append([]byte{gifExtensionIntroducer, gifApplicationLabel, byte(len(gifC2PAIdentifier))}, gifC2PAIdentifier...)
	decoy = append(decoy, gifSubBlockChain([]byte("not a real store"))...)

	data := gifFile(gifImage(decoy))
	if got := gifJUMBF(context.Background(), data); got != nil {
		t.Errorf("a marker inside image data must not be read as a store, got %q", got)
	}
}

func TestGIFJUMBF_Absent(t *testing.T) {
	data := gifFile(gifOtherExtension("NETSCAPE", []byte{1, 0, 0}), gifImage([]byte{0x44, 0x01}))
	if got := gifJUMBF(context.Background(), data); got != nil {
		t.Errorf("got %q, want nil", got)
	}
}

func TestGIFJUMBF_NotGIF(t *testing.T) {
	for _, in := range [][]byte{nil, []byte("GIF"), []byte("GIF89a"), []byte("\xff\xd8\xff\xe0 jpeg not gif at all")} {
		if got := gifJUMBF(context.Background(), in); got != nil {
			t.Errorf("input %q: got %q, want nil", in, got)
		}
	}
}

func TestGIFJUMBF_UnterminatedSubBlockChain(t *testing.T) {
	// A sub-block declaring more bytes than remain, with no terminator.
	data := append([]byte("GIF89a"), 1, 0, 1, 0, 0, 0, 0)
	data = append(data, gifExtensionIntroducer, gifApplicationLabel, byte(len(gifC2PAIdentifier)))
	data = append(data, gifC2PAIdentifier...)
	data = append(data, 0xFF, 'a', 'b') // claims 255 bytes, supplies two

	if got := gifJUMBF(context.Background(), data); got != nil {
		t.Errorf("an unterminated chain must yield nil, got %q", got)
	}
}

func TestGIFJUMBF_EveryTruncation(t *testing.T) {
	store := []byte("\x00\x00\x00\x08jumbpayload")
	full := gifFile(gifOtherExtension("NETSCAPE", []byte{1}), gifC2PAExtension(store))

	for n := range len(full) {
		if got := gifJUMBF(context.Background(), full[:n]); got != nil && !bytes.Equal(got, store) {
			t.Fatalf("truncation at %d produced a store that is not the real one: %q", n, got)
		}
	}
	if got := gifJUMBF(context.Background(), full); !bytes.Equal(got, store) {
		t.Fatalf("the untruncated file must still yield the store, got %q", got)
	}
}

func TestGIFJUMBF_CancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if got := gifJUMBF(ctx, gifFile(gifC2PAExtension([]byte("store")))); got != nil {
		t.Errorf("cancelled context must yield nil, got %q", got)
	}
}

func FuzzGIFParse(f *testing.F) {
	f.Add(gifFile(gifC2PAExtension([]byte("\x00\x00\x00\x08jumb"))))
	f.Add(gifFile(gifImage([]byte{0x44, 0x01})))
	f.Add(gifFile(gifOtherExtension("NETSCAPE", []byte{1, 0, 0})))
	f.Add([]byte("GIF89a\x01\x00\x01\x00\x80\x00\x00\x21\xff\x0b"))

	f.Fuzz(func(t *testing.T, data []byte) {
		store := gifJUMBF(context.Background(), data)
		if store == nil {
			return
		}
		// Sub-blocks are reassembled into a fresh buffer, so the store can never
		// exceed the input it was built from.
		if len(store) > len(data) {
			t.Fatalf("returned %d bytes from a %d-byte input", len(store), len(data))
		}
	})
}
