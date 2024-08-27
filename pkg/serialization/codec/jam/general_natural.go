package jam

import (
	"encoding/binary"
	"math"
)

// SerializeUint64 implements the general formula (able to encode naturals of up to 2^64)
func SerializeUint64(x uint64) []byte {
	var l uint8
	// Determine the length needed to represent the value
	for l = 0; l < 8; l++ {
		if x < (1 << (7 * (l + 1))) {
			break
		}
	}
	bytes := make([]byte, 0)
	if l < 8 {
		// Calculate the prefix byte, ensure it stays within uint8 range
		prefix := uint8((256 - (1 << (8 - l))) + (x>>(8*l))&math.MaxUint8)
		bytes = append(bytes, prefix)
	} else {
		bytes = append(bytes, math.MaxUint8)
	}
	// Serialize the integer in little-endian order
	for i := 0; i < int(l); i++ {
		byteVal := uint8((x >> (8 * i)) & math.MaxUint8)
		bytes = append(bytes, byteVal)
	}
	return bytes
}

// DeserializeUint64WithLength deserializes a byte slice into a uint64 value, with length `l`.
func DeserializeUint64WithLength(serialized []byte, l uint8, u *uint64) error {
	*u = 0

	n := len(serialized)
	if n == 0 {
		return nil
	}

	if n > 8 {
		if serialized[0] != math.MaxUint8 {
			return errFirstByteNineByteSerialization
		}
		*u = binary.LittleEndian.Uint64(serialized[1:9])
		return nil
	}

	// Deserialize the first `l` bytes
	for i := uint8(0); i < l; i++ {
		*u |= uint64(serialized[i+1]) << (8 * i)
	}

	// Combine the remaining part of the prefix
	*u |= uint64(serialized[0]&(math.MaxUint8>>l)) << (8 * l)

	return nil
}
