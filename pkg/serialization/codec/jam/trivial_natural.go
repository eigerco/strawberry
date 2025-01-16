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

func deserializeTrivialNatural[T ~uint8 | ~uint16 | ~uint32 | ~uint64](serialized []byte, u *T) {
	*u = 0

	// Iterate over each byte in the serialized array
	for i := 0; i < len(serialized); i++ {
		*u |= T(serialized[i]) << (8 * i)
	}
}
