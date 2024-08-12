package codec

import (
	"encoding/binary"
	"fmt"
	"math"
	"math/bits"
)

// JAMCodec implements the Codec interface for GP (appendix c) serialization.
type JAMCodec struct{}

func (j *JAMCodec) Marshal(v interface{}) ([]byte, error) {
	return j.marshal(v)
}

func (j *JAMCodec) Unmarshal(data []byte, v interface{}) error {
	return j.unmarshal(data, v)
}

// Marshal encodes the data based on its type.
func (j *JAMCodec) marshal(v interface{}) ([]byte, error) {
	switch t := v.(type) {
	case uint64:
		return j.serializeUint64(t), nil
	case []byte:
		return append([]byte{}, t...), nil
	default:
		return nil, fmt.Errorf(unsupportedType, t)
	}
}

// Unmarshal decodes the data into the appropriate type.
func (j *JAMCodec) unmarshal(data []byte, v interface{}) error {
	switch t := v.(type) {
	case *uint64:
		return j.deserializeUint64(data, t)
	case *[]byte:
		*t = append([]byte{}, data...)
		return nil
	default:
		return fmt.Errorf(unsupportedType, t)
	}
}

// serializeUint64 serializes a uint64 value to a byte slice.
func (j *JAMCodec) serializeUint64(x uint64) []byte {
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

// deserializeUint64 deserializes a byte slice into a uint64 value.
func (j *JAMCodec) deserializeUint64(serialized []byte, u *uint64) error {
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
