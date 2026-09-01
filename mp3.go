package c2pa

import (
	"bytes"
	"context"
	"encoding/binary"
)

const (
	// id3C2PAMime is the GEOB frame's MIME type; the deprecated spelling is
	// still written by older producers.
	id3C2PAMime           = "application/c2pa"
	id3C2PAMimeDeprecated = "application/x-c2pa-manifest-store"
	// maxID3Frames bounds the frame walk.
	maxID3Frames = 4096
)

// mp3JUMBF returns the raw JUMBF manifest store from an MP3's ID3v2 tag, or nil
// when there is none.
//
// The store is a GEOB (general encapsulated object) frame whose MIME type is
// application/c2pa. GEOB's body is an encoding byte, then three
// terminated strings — MIME, filename, description — and only then the object,
// so the payload's offset depends on text the file controls.
//
// An unsynchronised tag (header flag 0x80) is not read: its bytes have been
// rewritten to avoid false frame syncs, and reading it as-is would return a
// corrupted store rather than nothing.
func mp3JUMBF(ctx context.Context, data []byte) []byte {
	if len(data) < 10 || string(data[:3]) != "ID3" {
		return nil
	}
	major, flags := data[3], data[5]
	if major < 3 || major > 4 || flags&0x80 != 0 {
		return nil
	}
	size := id3Synchsafe(data[6:10])
	end := min(10+size, len(data))

	pos := 10
	if flags&0x40 != 0 { // extended header, whose own size prefix is skipped
		if pos+4 > end {
			return nil
		}
		extSize := id3Synchsafe(data[pos : pos+4])
		if major == 3 {
			extSize = int(binary.BigEndian.Uint32(data[pos:pos+4])) + 4
		}
		pos += extSize
	}

	for frames := 0; frames < maxID3Frames && pos+10 <= end; frames++ {
		if ctx.Err() != nil {
			return nil
		}
		id := string(data[pos : pos+4])
		if id == "\x00\x00\x00\x00" {
			return nil // padding: the frames are done
		}
		// v2.4 sizes are synchsafe; v2.3 sizes are plain big-endian.
		frameSize := int(binary.BigEndian.Uint32(data[pos+4 : pos+8]))
		if major == 4 {
			frameSize = id3Synchsafe(data[pos+4 : pos+8])
		}
		body := pos + 10
		if frameSize <= 0 || body+frameSize > end {
			return nil
		}
		if id == "GEOB" {
			if store := id3GEOBStore(data[body : body+frameSize]); store != nil {
				return store
			}
		}
		pos = body + frameSize
	}
	return nil
}

// id3GEOBStore returns the object bytes of a GEOB frame body when its MIME type
// marks it as a C2PA manifest store, or nil otherwise.
func id3GEOBStore(body []byte) []byte {
	if len(body) < 2 {
		return nil
	}
	encoding := body[0]
	rest := body[1:]

	// The MIME type is ISO-8859-1 and NUL-terminated whatever the encoding byte
	// says — only filename and description follow the declared encoding.
	i := bytes.IndexByte(rest, 0)
	if i < 0 {
		return nil
	}
	mime := string(rest[:i])
	if mime != id3C2PAMime && mime != id3C2PAMimeDeprecated {
		return nil
	}
	rest = rest[i+1:]

	for range 2 { // filename, then description
		n := id3TerminatorLen(encoding)
		j := id3IndexTerminator(rest, n)
		if j < 0 {
			return nil
		}
		rest = rest[j+n:]
	}
	if len(rest) == 0 {
		return nil
	}
	return rest
}

// id3TerminatorLen is 2 for the UTF-16 encodings, whose NUL is two bytes.
func id3TerminatorLen(encoding byte) int {
	if encoding == 1 || encoding == 2 {
		return 2
	}
	return 1
}

// id3IndexTerminator finds a terminator of n bytes, aligned to n.
func id3IndexTerminator(b []byte, n int) int {
	for i := 0; i+n <= len(b); i += n {
		if bytes.Equal(b[i:i+n], make([]byte, n)) {
			return i
		}
	}
	return -1
}

// id3Synchsafe decodes ID3's 7-bits-per-byte integer, whose high bits are
// always clear so the value can never look like a frame sync.
func id3Synchsafe(b []byte) int {
	if len(b) < 4 {
		return 0
	}
	return int(b[0]&0x7F)<<21 | int(b[1]&0x7F)<<14 | int(b[2]&0x7F)<<7 | int(b[3]&0x7F)
}
