package jam

import (
	"fmt"
	"math"
	"math/bits"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEncodeDecodeUint64(t *testing.T) {
	testCases := []struct {
		input    uint64
		expected []byte
	}{
		// l = 0
		{0, []byte{0}},
		{1, []byte{1}},
		{math.MaxInt8, []byte{127}}, // 127
		// l = 1
		{1 << 7, []byte{128, 128}},        // 128
		{math.MaxUint8, []byte{128, 255}}, // 255
		{1 << 8, []byte{129, 0}},          // 256
		{(1 << 10) - 1, []byte{131, 255}}, // 1023
		{1 << 10, []byte{132, 0}},         // 1024
		{(1 << 14) - 1, []byte{191, 255}}, // 16383
		//l = 2
		{1 << 14, []byte{192, 0, 64}},           // 16384
		{math.MaxUint16, []byte{192, 255, 255}}, // 65535
		{1 << 16, []byte{193, 0, 0}},            // 65536
		{(1 << 21) - 1, []byte{223, 255, 255}},  // 2097151
		//l = 3
		{1 << 21, []byte{224, 0, 0, 32}},            // 2097152
		{(1 << 28) - 1, []byte{239, 255, 255, 255}}, // 268435455
		//l = 4
		{1 << 28, []byte{240, 0, 0, 0, 16}},              // 268435456
		{(1 << 35) - 1, []byte{247, 255, 255, 255, 255}}, // 34359738367
		//l = 5
		{1 << 35, []byte{248, 0, 0, 0, 0, 8}},                 // 34359738368
		{(1 << 42) - 1, []byte{251, 255, 255, 255, 255, 255}}, // 4398046511103
		//l = 6
		{1 << 42, []byte{252, 0, 0, 0, 0, 0, 4}},                   // 4398046511104
		{(1 << 49) - 1, []byte{253, 255, 255, 255, 255, 255, 255}}, // 562949953421311
		//l = 7
		{1 << 49, []byte{254, 0, 0, 0, 0, 0, 0, 2}},                     // 562949953421312
		{(1 << 56) - 1, []byte{254, 255, 255, 255, 255, 255, 255, 255}}, // 72057594037927935
		// l = 8
		{1 << 56, []byte{255, 0, 0, 0, 0, 0, 0, 0, 1}},   // 72057594037927936
		{1 << 63, []byte{255, 0, 0, 0, 0, 0, 0, 0, 128}}, // 9223372036854775808
	}

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("uint64(%d)", tc.input), func(t *testing.T) {
			// Marshal the x value
			serialized := serializeUint64(tc.input)

			// Check if the serialized output matches the expected output
			assert.Equal(t, tc.expected, serialized, "serialized output mismatch for x %d", tc.input)

			var l uint8
			if len(serialized) > 0 {
				l = uint8(bits.LeadingZeros8(^serialized[0]))
			}
			// Unmarshal the serialized data back into a uint64
			var deserialized uint64
			err := deserializeUint64WithLength(serialized, l, &deserialized)
			require.NoError(t, err, "unmarshal(%v) returned an unexpected error", serialized)

			// Check if the deserialized value matches the original x
			assert.Equal(t, tc.input, deserialized, "deserialized value mismatch for x %d", tc.input)
		})
	}
}
