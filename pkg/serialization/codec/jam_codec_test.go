package codec_test

import (
	"fmt"
	"math"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/eigerco/strawberry/pkg/serialization/codec"
)

func TestMarshalUnmarshalUint64(t *testing.T) {
	testCases := []struct {
		input    uint64
		expected []byte
	}{
		{0, []byte{0}},
		{1, []byte{1}},
		{math.MaxInt8, []byte{127}},
		{128, []byte{128, 128}},
		{math.MaxUint8, []byte{128, 255}},
		{256, []byte{129, 0}},
		{1023, []byte{131, 255}},
		{1024, []byte{132, 0}},
		{16383, []byte{191, 255}},
		{math.MaxUint16, []byte{192, 255, 255}},
		{65536, []byte{193, 0, 0}},
		{1 << 63, []byte{255, 0, 0, 0, 0, 0, 0, 0, 128}},
	}

	j := codec.JAMCodec{}

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("uint64(%d)", tc.input), func(t *testing.T) {
			// Marshal the input value
			serialized, err := j.Marshal(tc.input)
			require.NoError(t, err, "marshal(%d) returned an unexpected error", tc.input)

			// Check if the serialized output matches the expected output
			assert.Equal(t, tc.expected, serialized, "serialized output mismatch for input %d", tc.input)

			// Unmarshal the serialized data back into a uint64
			var deserialized uint64
			err = j.Unmarshal(serialized, &deserialized)
			require.NoError(t, err, "unmarshal(%v) returned an unexpected error", serialized)

			// Check if the deserialized value matches the original input
			assert.Equal(t, tc.input, deserialized, "deserialized value mismatch for input %d", tc.input)
		})
	}
}

func TestMarshalUnmarshalByteSlice(t *testing.T) {
	j := codec.JAMCodec{}

	data := []byte{1, 2, 3, 4}
	serialized, err := j.Marshal(data)
	require.NoError(t, err, "marshal(%d) returned an unexpected error", data)
	assert.Equal(t, data, serialized, "serialized output mismatch for input %d", data)

	var deserialized []byte
	err = j.Unmarshal(serialized, &deserialized)
	require.NoError(t, err, "unmarshal(%v) returned an unexpected error", serialized)

	assert.Equal(t, data, deserialized, "deserialized value mismatch for input %d", data)
}
