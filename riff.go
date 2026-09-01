package c2pa

import (
	"context"
	"encoding/binary"
)

// maxRIFFChunks bounds the top-level chunk walk. A RIFF file of nothing but
// empty 8-byte chunks would otherwise cost one iteration per 8 bytes; the cap
// is far above any real file's top-level chunk count.
const maxRIFFChunks = 1 << 16

// riffC2PAChunk is the FourCC of the chunk carrying the manifest store.
const riffC2PAChunk = "C2PA"

// riffJUMBF returns the raw JUMBF manifest store from a RIFF asset — WebP, WAV
// or AVI — or nil when there is none.
//
// The store is a top-level chunk with FourCC C2PA, sitting directly inside the
// outer RIFF container alongside the format's own chunks. WebP's VP8X flags
// matter only when writing; a reader just finds the chunk. An AVI larger than
// 1 GB continues into further RIFF/AVIX containers, but the store is in the
// first, so only that one is walked.
//
// Nothing here trusts a declared size: a chunk claiming more bytes than the
// file holds is where a RIFF reader gets exploited.
func riffJUMBF(ctx context.Context, data []byte) []byte {
	// "RIFF" + size + form type, then the chunks.
	if len(data) < 12 || string(data[:4]) != "RIFF" {
		return nil
	}
	// The declared RIFF size covers everything after it, but a truncated or
	// lying file is normal input here — the real bytes are the only bound.
	end := len(data)
	if declared := int64(binary.LittleEndian.Uint32(data[4:8])) + 8; declared >= 12 && declared < int64(end) {
		end = int(declared)
	}

	for pos, chunks := 12, 0; pos+8 <= end && chunks < maxRIFFChunks; chunks++ {
		if ctx.Err() != nil {
			return nil
		}
		id := string(data[pos : pos+4])
		size := int64(binary.LittleEndian.Uint32(data[pos+4 : pos+8]))
		body := int64(pos) + 8
		if body+size > int64(end) {
			return nil // declared past the end: stop rather than read into whatever follows
		}
		if id == riffC2PAChunk {
			return data[body : body+size]
		}
		// Chunks are word-aligned: an odd-sized body is followed by a pad byte.
		pos = int(body + size + size%2)
	}
	return nil
}
