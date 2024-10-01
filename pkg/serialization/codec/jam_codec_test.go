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

func TestEncodeDecodeMap(t *testing.T) {
	j := JAMCodec{}

	// Define a map with int keys and int values
	input := map[int]int{
		1: 100,
		2: 200,
		3: 300,
	}

	// Marshal the map
	serialized, err := j.Marshal(input)
	require.NoError(t, err)

	// Unmarshal the serialized data back into a map
	var deserialized map[int]int
	err = j.Unmarshal(serialized, &deserialized)
	require.NoError(t, err, "unmarshal(%v) returned an unexpected error", serialized)

	// Check if the deserialized value matches the original input
	assert.Equal(t, input, deserialized, "deserialized map mismatch for input %v", input)
}

func TestEncodeDecodeMapUnsupportedKeyType(t *testing.T) {
	j := JAMCodec{}

	// Define a map with an unsupported key type (e.g., complex numbers as keys)
	input := map[complex128]int{
		complex(1, 2): 100,
		complex(3, 4): 200,
	}

	// Attempt to marshal the map and expect an error
	_, err := j.Marshal(input)
	require.Error(t, err, "expected an error when using an unsupported key type")

	// Ensure the error matches the expected error for unsupported map key type
	expectedError := "encoding map field: unsupported map key type complex128"
	assert.Contains(t, err.Error(), expectedError, "unexpected error message")
}

func TestEncodeDecodeMapUnsortedKeys(t *testing.T) {
	j := JAMCodec{}

	// Define a map with unsorted integer keys
	input := map[int]int{
		5: 500,
		1: 100,
		3: 300,
		2: 200,
		4: 400,
	}

	// Marshal the map
	serialized, err := j.Marshal(input)
	require.NoError(t, err)

	// Unmarshal the serialized data back into a map
	var deserialized map[int]int
	err = j.Unmarshal(serialized, &deserialized)
	require.NoError(t, err, "unmarshal(%v) returned an unexpected error", serialized)

	// Define the expected output (keys sorted in ascending order)
	expected := map[int]int{
		1: 100,
		2: 200,
		3: 300,
		4: 400,
		5: 500,
	}

	// Check if the deserialized value matches the expected sorted output
	assert.Equal(t, expected, deserialized, "deserialized map should have sorted keys")
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
