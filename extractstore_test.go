package c2pa

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"testing"
)

func TestExtractStore_EveryContainer(t *testing.T) {
	cases := []struct {
		name      string
		file      string
		container Container
	}{
		{"jpeg", "testdata/c2pa_signed.jpg", JPEG},
		{"png", "testdata/c2pa_2x_openai.png", PNG},
		{"bmff", "testdata/c2pa_signed_video.mp4", BMFF},
		{"pdf", "testdata/c2pa_chatgpt.pdf", PDF},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f, err := os.Open(tc.file)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = f.Close() }()

			store, err := ExtractStore(context.Background(), tc.container, f)
			if err != nil {
				t.Fatalf("ExtractStore: %v", err)
			}
			if len(store) == 0 {
				t.Fatal("ExtractStore returned no store for a signed fixture")
			}
			// A store is a JUMBF superbox: 4-byte LBox then the 'jumb' TBox.
			if len(store) < 8 || string(store[4:8]) != "jumb" {
				t.Fatalf("store does not begin with a jumb superbox: % x", store[:min(len(store), 16)])
			}

			// The walker must reach the claim signature every signed manifest has.
			var tboxes []string
			WalkBoxes(context.Background(), store, func(_, tbox string, _ []byte) {
				tboxes = append(tboxes, tbox)
			})
			if len(tboxes) == 0 {
				t.Fatal("WalkBoxes found no leaf boxes in the extracted store")
			}
		})
	}
}

// TestExtractStore_ReachesAssertionsInfoDoesNotModel is the manifest-viewer
// case the export exists for: JSON assertion payloads Info never surfaces.
func TestExtractStore_ReachesAssertionsInfoDoesNotModel(t *testing.T) {
	f, err := os.Open("testdata/c2pa_signed.jpg")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()

	store, err := ExtractStore(context.Background(), JPEG, f)
	if err != nil {
		t.Fatal(err)
	}

	var jsonPayloads int
	WalkBoxes(context.Background(), store, func(_, tbox string, content []byte) {
		if tbox != "json" {
			return
		}
		var v any
		if json.Unmarshal(content, &v) == nil {
			jsonPayloads++
		}
	})
	if jsonPayloads == 0 {
		t.Error("no decodable json assertion payloads reachable through ExtractStore + WalkBoxes")
	}
}

func TestExtractStore_NoManifest(t *testing.T) {
	store, err := ExtractStore(context.Background(), JPEG, bytes.NewReader([]byte("\xff\xd8\xff\xe0 no manifest here")))
	if err != nil {
		t.Fatalf("a file without a manifest is not an error: %v", err)
	}
	if store != nil {
		t.Errorf("expected nil store, got %d bytes", len(store))
	}
}

func TestExtractStore_EmptyAndUnknownContainer(t *testing.T) {
	if store, err := ExtractStore(context.Background(), JPEG, bytes.NewReader(nil)); err != nil || store != nil {
		t.Errorf("empty input: store=%v err=%v, want nil/nil", store, err)
	}
	if store, err := ExtractStore(context.Background(), Container("tiff"), bytes.NewReader([]byte("whatever"))); err != nil || store != nil {
		t.Errorf("unknown container: store=%v err=%v, want nil/nil", store, err)
	}
}

func TestExtractStore_CancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := ExtractStore(ctx, JPEG, bytes.NewReader([]byte("\xff\xd8"))); !errors.Is(err, context.Canceled) {
		t.Errorf("err=%v, want context.Canceled", err)
	}
}

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errors.New("boom") }

func TestExtractStore_ReaderError(t *testing.T) {
	if _, err := ExtractStore(context.Background(), JPEG, errReader{}); err == nil {
		t.Error("expected the reader's error to surface")
	}
}
