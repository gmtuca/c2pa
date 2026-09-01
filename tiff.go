package c2pa

import (
	"context"
	"encoding/binary"
)

const (
	// tiffC2PATag is the private IFD tag carrying the manifest store.
	tiffC2PATag = 0xCD41
	// tiffUndefined is TIFF field type 7 (UNDEFINED), one byte per element, which
	// is what the store is written as.
	tiffUndefined = 7
	// maxTIFFIFDHops bounds the IFD chain. A next-IFD offset may point anywhere,
	// including backwards, so the chain can be made circular.
	maxTIFFIFDHops = 64
)

// tiffJUMBF returns the raw JUMBF manifest store from a TIFF or DNG asset, or
// nil when there is none. DNG is TIFF, so both are the same walk.
//
// The store lives in IFD tag 0xCD41 with field type UNDEFINED. Every IFD in the
// chain is checked, since a producer may place it on a later page.
//
// BigTIFF (magic 43, 8-byte offsets) is deliberately not read: it is a distinct
// layout, and returning nil is better than misreading one.
func tiffJUMBF(ctx context.Context, data []byte) []byte {
	if len(data) < 8 {
		return nil
	}
	var bo binary.ByteOrder
	switch string(data[:2]) {
	case "II":
		bo = binary.LittleEndian
	case "MM":
		bo = binary.BigEndian
	default:
		return nil
	}
	if bo.Uint16(data[2:4]) != 42 {
		return nil // 43 is BigTIFF; anything else is not TIFF at all
	}

	next := int64(bo.Uint32(data[4:8]))
	for hop := 0; hop < maxTIFFIFDHops && next > 0; hop++ {
		if ctx.Err() != nil {
			return nil
		}
		if next+2 > int64(len(data)) {
			return nil
		}
		ifd := int(next)
		count := int(bo.Uint16(data[ifd : ifd+2]))
		entries := ifd + 2
		// Each entry is 12 bytes, then a 4-byte offset to the next IFD.
		if int64(entries)+int64(count)*12+4 > int64(len(data)) {
			return nil
		}
		for i := range count {
			e := entries + i*12
			if int(bo.Uint16(data[e:e+2])) != tiffC2PATag {
				continue
			}
			if int(bo.Uint16(data[e+2:e+4])) != tiffUndefined {
				continue // the tag number alone does not make it a manifest store
			}
			size := int64(bo.Uint32(data[e+4 : e+8]))
			if size <= 0 {
				return nil
			}
			// Up to four bytes live in the value field itself; more is an offset.
			if size <= 4 {
				return data[e+8 : e+8+int(size)]
			}
			off := int64(bo.Uint32(data[e+8 : e+12]))
			if off < 8 || off+size > int64(len(data)) {
				return nil
			}
			return data[off : off+size]
		}
		next = int64(bo.Uint32(data[entries+count*12:]))
	}
	return nil
}
