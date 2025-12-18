package jam

import (
	"math"
)

func serializeTrivialNatural[T ~uint8 | ~uint16 | ~uint32 | ~uint64](x T, l uint) []byte {
	bytes := make([]byte, l)
	for i := uint(0); i < l; i++ {
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
	return []byte{byte(v), byte(v >> 8)}
}

// EncodeUint32 encodes a uint32 to little-endian bytes (eq. C.12)
func EncodeUint32(v uint32) []byte {
	return []byte{byte(v), byte(v >> 8), byte(v >> 16), byte(v >> 24)}
}

// EncodeUint64 encodes a uint64 to little-endian bytes (eq. C.12)
func EncodeUint64(v uint64) []byte {
	return []byte{
		byte(v), byte(v >> 8), byte(v >> 16), byte(v >> 24),
		byte(v >> 32), byte(v >> 40), byte(v >> 48), byte(v >> 56),
	}
}
