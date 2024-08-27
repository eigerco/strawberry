package codec

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEncodeDecodeSlice(t *testing.T) {
	j := JAMCodec{}

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

func TestEncodeDecodeArray(t *testing.T) {
	j := JAMCodec{}

	input := [4]byte{1, 2, 3, 4}
	// Marshal the input value
	serialized, err := j.Marshal(input)
	require.NoError(t, err)

	// Check if the serialized output matches the expected output
	assert.Equal(t, []byte{1, 2, 3, 4}, serialized, "serialized output mismatch for input %d", input)

	// Unmarshal the serialized data back into byte
	var deserialized [4]byte
	err = j.Unmarshal(serialized, &deserialized)
	require.NoError(t, err, "unmarshal(%v) returned an unexpected error", serialized)

	// Check if the deserialized value matches the original input
	assert.Equal(t, input, deserialized, "deserialized value mismatch for input %d", input)
}

func TestEncodeDecodeBool(t *testing.T) {
	j := JAMCodec{}

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
