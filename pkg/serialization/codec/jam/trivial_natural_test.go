package jam

import (
	"fmt"
	"math"
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEncodeDecodeTrivialUint8(t *testing.T) {
	tn := TrivialNatural[uint8]{}
	testCases := []struct {
		x        uint8
		l        uint8
		expected []byte
	}{
		{0, 1, []byte{0}},
		{1, 3, []byte{1, 0, 0}},
		{math.MaxInt8, 4, []byte{127, 0, 0, 0}},
		{math.MaxUint8, 2, []byte{255, 0}},
	}

	testEncodeDecodeTrivialUint(t, tn, testCases)
}

func TestEncodeDecodeTrivialUint16(t *testing.T) {
	tn := TrivialNatural[uint16]{}
	testCases := []struct {
		x        uint16
		l        uint8
		expected []byte
	}{
		{0, 1, []byte{0}},
		{math.MaxUint16, 2, []byte{255, 255}},
	}

	testEncodeDecodeTrivialUint(t, tn, testCases)
}

func TestEncodeDecodeTrivialUint32(t *testing.T) {
	tn := TrivialNatural[uint32]{}
	testCases := []struct {
		x        uint32
		l        uint8
		expected []byte
	}{
		{0, 1, []byte{0}},
		{1, 3, []byte{1, 0, 0}},
		{math.MaxInt8, 4, []byte{127, 0, 0, 0}},
		{128, 1, []byte{128}},
		{math.MaxUint8, 3, []byte{255, 0, 0}},
		{256, 2, []byte{0, 1}},
		{1023, 3, []byte{255, 3, 0}},
		{1024, 2, []byte{0, 4}},
		{16383, 4, []byte{255, 63, 0, 0}},
		{math.MaxUint16, 3, []byte{255, 255, 0}},
		{math.MaxUint32, 4, []byte{255, 255, 255, 255}},
	}

	testEncodeDecodeTrivialUint(t, tn, testCases)
}

func TestEncodeDecodeTrivialUint64(t *testing.T) {
	tn := TrivialNatural[uint64]{}
	testCases := []struct {
		x        uint64
		l        uint8
		expected []byte
	}{
		{0, 4, []byte{0, 0, 0, 0}},
		{1, 3, []byte{1, 0, 0}},
		{math.MaxUint16, 3, []byte{255, 255, 0}},
		{math.MaxUint32, 6, []byte{255, 255, 255, 255, 0, 0}},
		{math.MaxUint64, 8, []byte{255, 255, 255, 255, 255, 255, 255, 255}},
	}

	testEncodeDecodeTrivialUint(t, tn, testCases)
}

func testEncodeDecodeTrivialUint[T uint8 | uint16 | uint32 | uint64](t *testing.T, tn TrivialNatural[T], testCases []struct {
	x        T
	l        uint8
	expected []byte
}) {
	typeName := reflect.TypeOf(*new(T)).Name()

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("%s(%v)", typeName, tc.x), func(t *testing.T) {
			// Marshal the x value
			serialized := tn.Serialize(tc.x, tc.l)

			// Check if the serialized output matches the expected output
			assert.Equal(t, tc.expected, serialized, "serialized output mismatch for x %v", tc.x)

			// Unmarshal the serialized data back into the type T
			var deserialized T
			err := tn.Deserialize(serialized, &deserialized)
			require.NoError(t, err, "unmarshal(%v) returned an unexpected error", serialized)

			// Check if the deserialized value matches the original x
			assert.Equal(t, tc.x, deserialized, "deserialized value mismatch for x %v", tc.x)
		})
	}
}
