package serialization

import (
	"fmt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"math"
	"testing"
)

func TestEncodeDecodeUint64(t *testing.T) {
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

	gn := GeneralNatural{}

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("uint64(%d)", tc.input), func(t *testing.T) {
			// Marshal the input value
			serialized := gn.SerializeUint64(tc.input)

			// Check if the serialized output matches the expected output
			assert.Equal(t, tc.expected, serialized, "serialized output mismatch for input %d", tc.input)

			// Unmarshal the serialized data back into a uint64
			var deserialized uint64
			err := gn.DeserializeUint64(serialized, &deserialized)
			require.NoError(t, err, "unmarshal(%v) returned an unexpected error", serialized)

			// Check if the deserialized value matches the original input
			assert.Equal(t, tc.input, deserialized, "deserialized value mismatch for input %d", tc.input)
		})
	}
}
