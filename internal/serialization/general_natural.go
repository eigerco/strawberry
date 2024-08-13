package serialization

import (
	"encoding/binary"
	"math"
	"math/bits"
)

// GeneralNatural implements the formula (274: able to encode naturals of up to 2^64)
type GeneralNatural struct{}

func (j *GeneralNatural) SerializeUint64(x uint64) []byte {
	if x == 0 {
		return []byte{0}
	}

	var l uint8
	var found bool

	// Determine the length needed to represent the value
	for i := 0; i < 8; i++ {
		if x >= (1<<(7*i)) && x < (1<<(7*(i+1))) {
			found = true
			break
		}
		l++
	}

	bytes := make([]byte, 0)

	if found {
		// Calculate the prefix byte, ensure it stays within uint8 range
		prefix := uint8((256 - (1 << (8 - l))) + (x>>(8*l))&math.MaxUint8)
		bytes = append(bytes, prefix)
	} else {
		bytes = append(bytes, math.MaxUint8)
		l = 8
	}

	// Serialize the integer in little-endian order
	for i := 0; i < int(l); i++ {
		byteVal := uint8((x >> (8 * i)) & math.MaxUint8)
		bytes = append(bytes, byteVal)
	}

	return bytes
}

// DeserializeUint64 deserializes a byte slice into a uint64 value.
func (j *GeneralNatural) DeserializeUint64(serialized []byte, u *uint64) error {
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

	prefix := serialized[0]
	l := uint8(bits.LeadingZeros8(^prefix))

	// Deserialize the first `l` bytes
	for i := uint8(0); i < l; i++ {
		*u |= uint64(serialized[i+1]) << (8 * i)
	}

	// Combine the remaining part of the prefix
	*u |= uint64(prefix&(math.MaxUint8>>l)) << (8 * l)

	return nil
}
