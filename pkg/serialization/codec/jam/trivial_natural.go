package jam

import (
	"math"
)

func SerializeTrivialNatural[T uint8 | uint16 | uint32 | uint64](x T, l uint8) []byte {
	bytes := make([]byte, 0, l) // Preallocate with length `l`
	for i := uint8(0); i < l; i++ {
		byteVal := byte((x >> (8 * i)) & T(math.MaxUint8))
		bytes = append(bytes, byteVal)
	}
	return bytes
}

func DeserializeTrivialNatural[T uint8 | uint16 | uint32 | uint64](serialized []byte, u *T) {
	*u = 0

	// Iterate over each byte in the serialized array
	for i := 0; i < len(serialized); i++ {
		*u |= T(serialized[i]) << (8 * i)
	}
}
