package codec

import (
	"math"
	"testing"

	"github.com/eigerco/strawberry/pkg/serialization/codec/jam"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDecodeErrors(t *testing.T) {
	codec := &JAMCodec[uint64]{}

	// Test with a non-pointer value
	var nonPointer int
	err := codec.Unmarshal([]byte{1}, nonPointer)
	require.Error(t, err)
	assert.Equal(t, jam.ErrNonPointerOrNil, err)

	// Test with a nil pointer
	var nilPointer *int
	err = codec.Unmarshal([]byte{1}, nilPointer)
	require.Error(t, err)
	assert.Equal(t, jam.ErrNonPointerOrNil, err)

	// Empty data
	var dst *int
	err = codec.Unmarshal([]byte{}, dst)
	require.Error(t, err)
	assert.Equal(t, jam.ErrEmptyData, err)
}

func TestEncodeDecodeSlice(t *testing.T) {
	j := JAMCodec[uint64]{}

	input := []byte{1, 2, 3, 4}
	// Marshal the input value
	serialized, err := j.Marshal(input)
	require.NoError(t, err)

	// Check if the serialized output matches the expected output
	assert.Equal(t, []byte{4, 1, 2, 3, 4}, serialized, "serialized output mismatch for input %d", input)

	// Unmarshal the serialized data back into byte
	var deserialized []byte
	err = j.Unmarshal(serialized, &deserialized)
	require.NoError(t, err, "unmarshal(%v) returned an unexpected error", serialized)

	// Check if the deserialized value matches the original input
	assert.Equal(t, input, deserialized, "deserialized value mismatch for input %d", input)
}

func TestEncodeDecodeLargeSlice(t *testing.T) {
	j := JAMCodec[uint64]{}
	// Create a large input slice
	input := make([]byte, math.MaxUint16) // 65536 elements, requires multiple bytes to encode the length
	for i := 0; i < len(input); i++ {
		input[i] = byte(i % 256)
	}

	serialized, err := j.Marshal(input)
	require.NoError(t, err)

	var deserialized []byte
	err = j.Unmarshal(serialized, &deserialized)
	require.NoError(t, err, "unmarshal(%v) returned an unexpected error", serialized)

	assert.Equal(t, input, deserialized, "deserialized value mismatch for input %d", input)

	var length uint64
	err = j.gn.DeserializeUint64(serialized, &length)
	require.NoError(t, err)

	assert.Equal(t, uint64(len(input)), length, "deserialized length mismatch")
}

func TestEncodeDecodeArray(t *testing.T) {
	j := JAMCodec[uint32]{}

	input := [4]byte{1, 2, 3, 4}
	// Marshal the input value
	serialized, err := j.Marshal(input)
	require.NoError(t, err)

	// Check if the serialized output matches the expected output
	assert.Equal(t, []byte{4, 1, 2, 3, 4}, serialized, "serialized output mismatch for input %d", input)

	// Unmarshal the serialized data back into byte
	var deserialized [4]byte
	err = j.Unmarshal(serialized, &deserialized)
	require.NoError(t, err, "unmarshal(%v) returned an unexpected error", serialized)

	// Check if the deserialized value matches the original input
	assert.Equal(t, input, deserialized, "deserialized value mismatch for input %d", input)
}

func TestEncodeDecodeBool(t *testing.T) {
	j := JAMCodec[uint32]{}

	input := true
	// Marshal the boolean value
	serialized, err := j.Marshal(input)
	require.NoError(t, err)

	// Check if the serialized output matches the expected output
	assert.Equal(t, []byte{1}, serialized, "serialized output mismatch for input %d", input)

	// Unmarshal the serialized data back into bool
	var deserialized bool
	err = j.Unmarshal(serialized, &deserialized)
	require.NoError(t, err, "unmarshal(%v) returned an unexpected error", serialized)

	// Check if the deserialized value matches the original input
	assert.Equal(t, input, deserialized, "deserialized value mismatch for input %d", input)

	input = false
	// Marshal the boolean value
	serialized, err = j.Marshal(input)
	require.NoError(t, err)

	// Check if the serialized output matches the expected output
	assert.Equal(t, []byte{0}, serialized, "serialized output mismatch for input %d", input)

	// Unmarshal the serialized data back into bool
	err = j.Unmarshal(serialized, &deserialized)
	require.NoError(t, err, "unmarshal(%v) returned an unexpected error", serialized)

	// Check if the deserialized value matches the original input
	assert.Equal(t, input, deserialized, "deserialized value mismatch for input %d", input)
}
