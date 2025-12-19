package jam

import (
	"math"
)

func serializeTrivialNatural[T ~uint8 | ~uint16 | ~uint32 | ~uint64](x T, l uint) []byte {
	bytes := make([]byte, l)
	for i := range l {
		bytes[i] = byte((x >> (8 * i)) & T(math.MaxUint8))
	}
	return bytes
}

// DecodeUint8 decodes a little-endian uint8 from bytes (eq. C.12)
func DecodeUint8(b []byte) uint8 {
	if len(b) == 0 {
		return 0
	}
	return b[0]
}

// DecodeUint16 decodes a little-endian uint16 from bytes (eq. C.12)
func DecodeUint16(b []byte) uint16 {
	var v uint16
	for i := range b {
		v |= uint16(b[i]) << (8 * i)
	}
	return v
}

// DecodeUint32 decodes a little-endian uint32 from bytes (eq. C.12)
func DecodeUint32(b []byte) uint32 {
	var v uint32
	for i := range b {
		v |= uint32(b[i]) << (8 * i)
	}
	return v
}

// DecodeUint64 decodes a little-endian uint64 from bytes (eq. C.12)
func DecodeUint64(b []byte) uint64 {
	var v uint64
	for i := range b {
		v |= uint64(b[i]) << (8 * i)
	}
	return v
}

// EncodeUint8 encodes a uint8 to little-endian bytes (eq. C.12)
func EncodeUint8(v uint8) []byte {
	return []byte{v}
}

// EncodeUint16 encodes a uint16 to little-endian bytes (eq. C.12)
func EncodeUint16(v uint16) []byte {
	b := make([]byte, 2)
	PutUint16(b, v)
	return b
}

// EncodeUint32 encodes a uint32 to little-endian bytes (eq. C.12)
func EncodeUint32(v uint32) []byte {
	b := make([]byte, 4)
	PutUint32(b, v)
	return b
}

// EncodeUint64 encodes a uint64 to little-endian bytes (eq. C.12)
func EncodeUint64(v uint64) []byte {
	b := make([]byte, 8)
	PutUint64(b, v)
	return b
}

// PutUint16 encodes a uint16 to little-endian bytes into an existing buffer
func PutUint16(b []byte, v uint16) {
	b[0] = byte(v)
	b[1] = byte(v >> 8)
}

// PutUint32 encodes a uint32 to little-endian bytes into an existing buffer
func PutUint32(b []byte, v uint32) {
	b[0] = byte(v)
	b[1] = byte(v >> 8)
	b[2] = byte(v >> 16)
	b[3] = byte(v >> 24)
}

// PutUint64 encodes a uint64 to little-endian bytes into an existing buffer
func PutUint64(b []byte, v uint64) {
	b[0] = byte(v)
	b[1] = byte(v >> 8)
	b[2] = byte(v >> 16)
	b[3] = byte(v >> 24)
	b[4] = byte(v >> 32)
	b[5] = byte(v >> 40)
	b[6] = byte(v >> 48)
	b[7] = byte(v >> 56)
}
