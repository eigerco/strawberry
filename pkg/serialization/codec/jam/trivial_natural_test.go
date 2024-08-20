package jam

import (
	"fmt"
	"math"
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSerializationTrivialNatural(t *testing.T) {
	testCases := []struct {
		x        any
		l        uint8
		expected []byte
	}{
		{uint8(1), 0, []byte{}},
		{uint8(0), 1, []byte{0}},
		{uint8(1), 3, []byte{1, 0, 0}},
		{uint8(math.MaxInt8), 4, []byte{127, 0, 0, 0}},
		{uint8(math.MaxUint8), 2, []byte{255, 0}},
		{uint16(0), 0, []byte{}},
		{uint16(0), 1, []byte{0}},
		{uint16(math.MaxUint16), 2, []byte{255, 255}},
		{uint32(0), 0, []byte{}},
		{uint32(0), 1, []byte{0}},
		{uint32(1), 3, []byte{1, 0, 0}},
		{uint32(math.MaxInt8), 4, []byte{127, 0, 0, 0}},
		{uint32(128), 1, []byte{128}},
		{uint32(math.MaxUint8), 3, []byte{255, 0, 0}},
		{uint32(256), 2, []byte{0, 1}},
		{uint32(1023), 3, []byte{255, 3, 0}},
		{uint32(1024), 2, []byte{0, 4}},
		{uint32(16383), 4, []byte{255, 63, 0, 0}},
		{uint32(math.MaxUint16), 3, []byte{255, 255, 0}},
		{uint32(math.MaxUint32), 4, []byte{255, 255, 255, 255}},
		{uint64(math.MaxUint64), 0, []byte{}},
		{uint64(0), 4, []byte{0, 0, 0, 0}},
		{uint64(1), 3, []byte{1, 0, 0}},
		{uint64(math.MaxUint16), 3, []byte{255, 255, 0}},
		{uint64(math.MaxUint32), 6, []byte{255, 255, 255, 255, 0, 0}},
		{uint64(math.MaxUint64), 8, []byte{255, 255, 255, 255, 255, 255, 255, 255}},
	}

	for _, tc := range testCases {
		testName := fmt.Sprintf("%s_%v", reflect.TypeOf(tc.x).Name(), tc.x)
		t.Run(testName, func(t *testing.T) {
			var serialized []byte
			switch v := tc.x.(type) {
			case uint8:
				serialized = SerializeTrivialNatural(v, tc.l)
			case uint16:
				serialized = SerializeTrivialNatural(v, tc.l)
			case uint32:
				serialized = SerializeTrivialNatural(v, tc.l)
			case uint64:
				serialized = SerializeTrivialNatural(v, tc.l)
			}

			assert.Equal(t, tc.expected, serialized, "serialized output mismatch")

			// Skip deserialization if l == 0
			if tc.l == 0 {
				return
			}

			switch v := tc.x.(type) {
			case uint8:
				var deserialized uint8
				DeserializeTrivialNatural(serialized, &deserialized)
				assert.Equal(t, v, deserialized, "deserialized value mismatch")
			case uint16:
				var deserialized uint16
				DeserializeTrivialNatural(serialized, &deserialized)
				assert.Equal(t, v, deserialized, "deserialized value mismatch")
			case uint32:
				var deserialized uint32
				DeserializeTrivialNatural(serialized, &deserialized)
				assert.Equal(t, v, deserialized, "deserialized value mismatch")
			case uint64:
				var deserialized uint64
				DeserializeTrivialNatural(serialized, &deserialized)
				assert.Equal(t, v, deserialized, "deserialized value mismatch")
			}
		})
	}
}
