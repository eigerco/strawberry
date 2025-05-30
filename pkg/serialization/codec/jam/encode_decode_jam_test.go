package jam_test

import (
	"crypto/ed25519"
	"io"
	"math"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/eigerco/strawberry/pkg/serialization/codec/jam"
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
	Bits       jam.BitSequence
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
		Bits: jam.BitSequence{
			true, true, true, true, true, true, true, true,
			true, true, true, true, true, true, true, false,
			true, true, true, true, true, true, false, false,
			true, true, true, true, false, false, false, false,
			true, true, false, false, false, false, false, false,
			true, false, false, false, false, false, false, false,
			false, false, false, false, false, false, false, false,
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

func TestLengthTag(t *testing.T) {
	// simple struct without tags
	type NoTag struct {
		Uint32 uint32
	}
	noTag := NoTag{10}
	marshaledData, err := jam.Marshal(noTag)
	require.NoError(t, err)
	require.Len(t, marshaledData, 4)
	require.Equal(t, []byte{10, 0, 0, 0}, marshaledData)

	var noTagUnmarshaled NoTag
	err = jam.Unmarshal(marshaledData, &noTagUnmarshaled)
	require.NoError(t, err)
	assert.Equal(t, noTag, noTagUnmarshaled)

	// simple struct with tag
	type WithTag struct {
		Uint32 uint32 `jam:"length=32"`
	}
	withTag := WithTag{50}
	marshaledData, err = jam.Marshal(withTag)
	require.NoError(t, err)
	require.Len(t, marshaledData, 32)
	expectedBytes := append([]byte{50}, make([]byte, 31)...)
	assert.Equal(t, expectedBytes, marshaledData)

	var withTagUnmarshaled WithTag
	err = jam.Unmarshal(marshaledData, &withTagUnmarshaled)
	require.NoError(t, err)
	assert.Equal(t, withTag, withTagUnmarshaled)

	// more complex struct to check alias and pointers
	type Alias uint16
	type CustomStruct struct {
		Alias      Alias   `jam:"length=6"`
		Uint32     uint32  `jam:"length=32"`
		NilPointer *uint8  `jam:"length=4"`
		Pointer    *uint64 `jam:"length=10"`
		Bool       bool
	}

	p := uint64(40)
	original := CustomStruct{
		Alias:   5,
		Uint32:  50,
		Pointer: &p,
		Bool:    true,
	}

	marshaledData, err = jam.Marshal(original)
	require.NoError(t, err)

	var unmarshaled CustomStruct
	err = jam.Unmarshal(marshaledData, &unmarshaled)
	require.NoError(t, err)

	assert.Equal(t, original, unmarshaled)
}

func TestCompactTag(t *testing.T) {
	// simple struct without tags
	type NoTag struct {
		Uint32 uint32
	}
	noTag := NoTag{10}
	marshaledData, err := jam.Marshal(noTag)
	require.NoError(t, err)
	require.Len(t, marshaledData, 4)
	require.Equal(t, []byte{10, 0, 0, 0}, marshaledData)

	var noTagUnmarshaled NoTag
	err = jam.Unmarshal(marshaledData, &noTagUnmarshaled)
	require.NoError(t, err)
	assert.Equal(t, noTag, noTagUnmarshaled)

	// simple struct with compact tag
	type WithTag struct {
		Uint32 uint32 `jam:"encoding=compact"`
	}
	withTag := WithTag{10}
	marshaledData, err = jam.Marshal(withTag)
	require.NoError(t, err)
	require.Len(t, marshaledData, 1)
	assert.Equal(t, []byte{10}, marshaledData)

	var withTagUnmarshaled WithTag
	err = jam.Unmarshal(marshaledData, &withTagUnmarshaled)
	require.NoError(t, err)
	assert.Equal(t, withTag, withTagUnmarshaled)
}

// Struct for testing custom marshalling.
type CustomStruct struct {
	First uint32
	Last  uint32
}

func (c CustomStruct) MarshalJAM() ([]byte, error) {
	// Swap the fields order for custom marshalling.
	custom := struct {
		Last  uint32
		First uint32
	}{
		Last:  c.Last,
		First: c.First,
	}
	return jam.Marshal(custom)
}

func (c *CustomStruct) UnmarshalJAM(reader io.Reader) error {
	custom := struct {
		Last  uint32
		First uint32
	}{}

	decoder := jam.NewDecoder(reader)
	err := decoder.Decode(&custom)
	if err != nil {
		return err
	}

	c.First = custom.First
	c.Last = custom.Last

	return nil
}

func TestCustomMarshalUnmarshal(t *testing.T) {
	original := CustomStruct{
		First: 10,
		Last:  20,
	}
	// Marshalled data will have the fields order swapped, Last then First.
	marshaledData, err := jam.Marshal(original)
	require.NoError(t, err)

	var unmarshaled CustomStruct
	err = jam.Unmarshal(marshaledData, &unmarshaled)
	require.NoError(t, err)

	// Unmarshalled data should get the order right.
	assert.Equal(t, original, unmarshaled)

	wrong := struct {
		First uint32
		Last  uint32
	}{}
	err = jam.Unmarshal(marshaledData, &wrong)
	require.NoError(t, err)

	// Simply decoding into another struct with the original order should swap
	// the fields.
	assert.NotEqual(t, original.First, wrong.First)
	assert.NotEqual(t, original.Last, wrong.Last)
	assert.Equal(t, original.First, wrong.Last)
	assert.Equal(t, original.Last, wrong.First)
}
