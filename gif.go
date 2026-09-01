package c2pa

import (
	"bytes"
	"context"
)

const (
	gifExtensionIntroducer = 0x21
	gifApplicationLabel    = 0xFF
	gifImageDescriptor     = 0x2C
	gifTrailer             = 0x3B
	// gifC2PAIdentifier is the 8-byte application identifier plus its 3-byte
	// authentication code, which together mark the C2PA application extension.
	gifC2PAIdentifier = "C2PA_GIF\x01\x00\x00"
	// maxGIFBlocks bounds the block walk over adversarial input.
	maxGIFBlocks = 1 << 16
)

// gifJUMBF returns the raw JUMBF manifest store from a GIF, or nil when there
// is none.
//
// The store rides in an application extension introduced by 0x21 0xFF, whose
// 11-byte header is the identifier "C2PA_GIF" and the authentication code
// 01 00 00. Its payload is split across data sub-blocks of at most 255 bytes,
// so it has to be reassembled rather than sliced.
//
// The block structure is walked properly rather than scanned for the marker:
// image data is arbitrary LZW bytes and can spell anything, so a scan would
// happily find a "store" inside a frame.
func gifJUMBF(ctx context.Context, data []byte) []byte {
	// "GIF" + version, then the logical screen descriptor.
	if len(data) < 13 || string(data[:3]) != "GIF" {
		return nil
	}
	pos := 13
	// A global colour table, when the packed field's high bit is set, is
	// 3 * 2^(n+1) bytes and sits before the first block.
	if packed := data[10]; packed&0x80 != 0 {
		pos += 3 * (1 << ((packed & 0x07) + 1))
	}

	for blocks := 0; pos < len(data) && blocks < maxGIFBlocks; blocks++ {
		if ctx.Err() != nil {
			return nil
		}
		switch data[pos] {
		case gifTrailer:
			return nil
		case gifExtensionIntroducer:
			if pos+2 > len(data) {
				return nil
			}
			label := data[pos+1]
			pos += 2
			if label == gifApplicationLabel {
				// The 11-byte identifier block is itself a sub-block.
				if pos < len(data) && int(data[pos]) == len(gifC2PAIdentifier) &&
					pos+1+len(gifC2PAIdentifier) <= len(data) &&
					string(data[pos+1:pos+1+len(gifC2PAIdentifier)]) == gifC2PAIdentifier {
					store, _ := gifSubBlocks(data, pos+1+len(gifC2PAIdentifier))
					return store
				}
			}
			_, next := gifSubBlocks(data, pos)
			if next < 0 {
				return nil
			}
			pos = next
		case gifImageDescriptor:
			// 10-byte descriptor, an optional local colour table, the LZW code
			// size byte, then the image's own sub-blocks.
			if pos+10 > len(data) {
				return nil
			}
			packed := data[pos+9]
			pos += 10
			if packed&0x80 != 0 {
				pos += 3 * (1 << ((packed & 0x07) + 1))
			}
			pos++ // LZW minimum code size
			_, next := gifSubBlocks(data, pos)
			if next < 0 {
				return nil
			}
			pos = next
		default:
			return nil // not a block boundary: stop rather than guess
		}
	}
	return nil
}

// gifSubBlocks reassembles the data sub-block chain starting at pos, returning
// the joined payload and the offset just past the terminating empty block.
// A chain that runs off the end returns next = -1.
func gifSubBlocks(data []byte, pos int) (payload []byte, next int) {
	var out bytes.Buffer
	for range maxGIFBlocks {
		if pos >= len(data) {
			return nil, -1
		}
		n := int(data[pos])
		if n == 0 {
			return out.Bytes(), pos + 1
		}
		if pos+1+n > len(data) {
			return nil, -1
		}
		out.Write(data[pos+1 : pos+1+n])
		pos += 1 + n
	}
	return nil, -1
}
