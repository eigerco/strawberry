package jam_test

import (
	"crypto/ed25519"
	"github.com/eigerco/strawberry/pkg/serialization/codec/jam"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"math"
	"testing"
)

type InnerStruct struct {
	Uint64 uint64
	Uint32 uint32
	Uint16 uint16
	Uint8  uint8
}
type TestStruct struct {
	IntField   int
	BoolField  bool
	LargeUint  uint
	PubKey     *ed25519.PublicKey
	InnerSlice []InnerStruct
}

func TestMarshalUnmarshal(t *testing.T) {
	original := TestStruct{
		BoolField: true,
		LargeUint: math.MaxUint,
		PubKey: &ed25519.PublicKey{
			0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
			0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
			0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
			0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0xFF,
		},
		InnerSlice: []InnerStruct{
			{1, 2, 3, 4},
			{2, 3, 4, 5},
			{3, 4, 5, 6},
		},
	}

	marshaledData, err := jam.Marshal(original)
	require.NoError(t, err)

	var unmarshaled TestStruct
	err = jam.Unmarshal(marshaledData, &unmarshaled)
	require.NoError(t, err)

	assert.Equal(t, original, unmarshaled)
}

func TestEmptyStruct(t *testing.T) {
	original := TestStruct{}

	marshaledData, err := jam.Marshal(original)
	require.NoError(t, err)

	var unmarshaled TestStruct
	err = jam.Unmarshal(marshaledData, &unmarshaled)
	require.NoError(t, err)

	assert.Equal(t, original, unmarshaled)
}

func TestMarshalUnmarshalWithPointer(t *testing.T) {
	type StructWithPointer struct {
		IntField *uint
	}
	intVal := uint(42)
	original := StructWithPointer{
		IntField: &intVal,
	}

	marshaledData, err := jam.Marshal(original)
	require.NoError(t, err)

	// Prepare a variable to hold the unmarshaled struct
	var unmarshaled StructWithPointer

	// Unmarshal the data back into the struct
	err = jam.Unmarshal(marshaledData, &unmarshaled)
	require.NoError(t, err)

	assert.Equal(t, original, unmarshaled)
}
