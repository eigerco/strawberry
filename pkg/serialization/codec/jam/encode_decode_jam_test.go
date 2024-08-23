package jam_test

import (
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
	InnerSlice []InnerStruct
}

func TestMarshalUnmarshal(t *testing.T) {
	original := TestStruct{
		BoolField: true,
		LargeUint: math.MaxUint,
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
