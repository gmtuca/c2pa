package c2pa

import (
	"bytes"
	"context"
	"encoding/binary"
	"testing"
)

// riffFile frames form + chunks as a RIFF container with an honest size.
func riffFile(form string, chunks ...[]byte) []byte {
	body := []byte(form)
	for _, c := range chunks {
		body = append(body, c...)
	}
	out := append([]byte("RIFF"), 0, 0, 0, 0)
	binary.LittleEndian.PutUint32(out[4:8], uint32(len(body)))
	return append(out, body...)
}

func TestRIFFJUMBF_EveryFormType(t *testing.T) {
	store := []byte("\x00\x00\x00\x10jumbnot-really-but-opaque")
	for _, form := range []string{"WEBP", "WAVE", "AVI "} {
		t.Run(form, func(t *testing.T) {
			data := riffFile(form,
				riffChunk("VP8L", []byte{1, 2, 3}),
				riffChunk(riffC2PAChunk, store),
				riffChunk("INFO", []byte{4, 5}),
			)
			if got := riffJUMBF(context.Background(), data); !bytes.Equal(got, store) {
				t.Errorf("got %q, want %q", got, store)
			}
		})
	}
}

func TestRIFFJUMBF_OddSizedChunkIsPadded(t *testing.T) {
	store := []byte("odd-store")
	// The preceding chunk has an odd body, so a pad byte separates it from the
	// C2PA chunk. Miss the pad and the walk lands one byte off and finds nothing.
	data := riffFile("WEBP",
		riffChunk("VP8 ", []byte{1, 2, 3}),
		riffChunk(riffC2PAChunk, store),
	)
	if got := riffJUMBF(context.Background(), data); !bytes.Equal(got, store) {
		t.Errorf("got %q, want %q", got, store)
	}
}

func TestRIFFJUMBF_Absent(t *testing.T) {
	data := riffFile("WAVE", riffChunk("fmt ", make([]byte, 16)), riffChunk("data", []byte{1, 2, 3, 4}))
	if got := riffJUMBF(context.Background(), data); got != nil {
		t.Errorf("got %q, want nil", got)
	}
}

func TestRIFFJUMBF_NotRIFF(t *testing.T) {
	for _, in := range [][]byte{
		nil,
		[]byte("RIF"),
		[]byte("RIFFshort"),
		[]byte("\xff\xd8\xff\xe0 a jpeg"),
		append([]byte("XIFF"), make([]byte, 32)...),
	} {
		if got := riffJUMBF(context.Background(), in); got != nil {
			t.Errorf("input %q: got %q, want nil", in, got)
		}
	}
}

// TestRIFFJUMBF_ForgedChunkSize is c2pa-rs's own hardening case: a tiny file
// whose C2PA chunk claims far more data than exists. Reading the declared
// length would run off the end of the buffer.
func TestRIFFJUMBF_ForgedChunkSize(t *testing.T) {
	data := append([]byte("RIFF"), 0, 0, 0, 0)
	binary.LittleEndian.PutUint32(data[4:8], 12)
	data = append(data, "WAVE"...)
	data = append(data, riffC2PAChunk...)
	data = binary.LittleEndian.AppendUint32(data, 0xFFFFFFFF) // 4 GiB of "payload"

	if got := riffJUMBF(context.Background(), data); got != nil {
		t.Errorf("a chunk claiming more than the file holds must yield nil, got %d bytes", len(got))
	}
}

// TestRIFFJUMBF_DeclaredRIFFSizeBoundsTheWalk keeps a store appended after the
// declared container from being read as though it belonged to the file.
func TestRIFFJUMBF_DeclaredRIFFSizeBoundsTheWalk(t *testing.T) {
	honest := riffFile("WEBP", riffChunk("VP8L", []byte{9}))
	appended := append(honest, riffChunk(riffC2PAChunk, []byte("appended-after-the-container"))...)

	if got := riffJUMBF(context.Background(), appended); got != nil {
		t.Errorf("store outside the declared RIFF size must not be returned, got %q", got)
	}
}

func TestRIFFJUMBF_ZeroSizedChunksTerminate(t *testing.T) {
	var chunks [][]byte
	for range 500 {
		chunks = append(chunks, riffChunk("null", nil))
	}
	store := []byte("after-the-empties")
	chunks = append(chunks, riffChunk(riffC2PAChunk, store))

	done := make(chan []byte, 1)
	go func() { done <- riffJUMBF(context.Background(), riffFile("WEBP", chunks...)) }()
	select {
	case got := <-done:
		if !bytes.Equal(got, store) {
			t.Errorf("got %q, want %q", got, store)
		}
	case <-t.Context().Done():
		t.Fatal("riffJUMBF did not terminate over empty chunks")
	}
}

// TestRIFFJUMBF_EveryTruncation asserts the parser never panics and never
// invents a store, whatever prefix of a good file it is handed.
func TestRIFFJUMBF_EveryTruncation(t *testing.T) {
	store := []byte("\x00\x00\x00\x08jumb")
	full := riffFile("WEBP", riffChunk("VP8L", []byte{1, 2, 3}), riffChunk(riffC2PAChunk, store))

	for n := range len(full) {
		got := riffJUMBF(context.Background(), full[:n])
		if got != nil && !bytes.Equal(got, store) {
			t.Fatalf("truncation at %d produced a store that is not the real one: %q", n, got)
		}
	}
	if got := riffJUMBF(context.Background(), full); !bytes.Equal(got, store) {
		t.Fatalf("the untruncated file must still yield the store, got %q", got)
	}
}

func TestRIFFJUMBF_CancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	data := riffFile("WEBP", riffChunk(riffC2PAChunk, []byte("store")))
	if got := riffJUMBF(ctx, data); got != nil {
		t.Errorf("cancelled context must yield nil, got %q", got)
	}
}

func FuzzRIFFParse(f *testing.F) {
	f.Add(riffFile("WEBP", riffChunk(riffC2PAChunk, []byte("\x00\x00\x00\x08jumb"))))
	f.Add(riffFile("WAVE", riffChunk("fmt ", make([]byte, 16))))
	f.Add(riffFile("AVI ", riffChunk("LIST", []byte{1, 2, 3}), riffChunk(riffC2PAChunk, nil)))
	f.Add([]byte("RIFF\xff\xff\xff\xffWEBPC2PA\xff\xff\xff\xff"))

	f.Fuzz(func(t *testing.T, data []byte) {
		store := riffJUMBF(context.Background(), data)
		if store == nil {
			return
		}
		// Anything returned must be a real slice of the input, never a read
		// beyond it — the property a forged length would violate.
		if len(store) > len(data) {
			t.Fatalf("returned %d bytes from a %d-byte input", len(store), len(data))
		}
	})
}
