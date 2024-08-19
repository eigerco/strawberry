package jam

import (
	"math"
)

// TrivialNatural implements the trivial integer formula
// (This is utilized for almost all integer encoding across the protocol)
type TrivialNatural[T uint8 | uint16 | uint32 | uint64] struct{}

// Serialize serializes any unsigned integer type into a byte slice.
func (j *TrivialNatural[T]) Serialize(x T, l uint8) []byte {
	bytes := make([]byte, 0, l) // Preallocate with length `l`
	for i := uint8(0); i < l; i++ {
		byteVal := byte((x >> (8 * i)) & T(math.MaxUint8))
		bytes = append(bytes, byteVal)
	}
	return bytes
}

// Deserialize deserializes a byte slice into the provided unsigned integer type.
func (j *TrivialNatural[T]) Deserialize(serialized []byte, u *T) {
	*u = 0

	// Iterate over each byte in the serialized array
	for i := 0; i < len(serialized); i++ {
		*u |= T(serialized[i]) << (8 * i)
	}
}
