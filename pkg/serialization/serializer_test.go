package serialization_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/eigerco/strawberry/pkg/serialization"
	"github.com/eigerco/strawberry/pkg/serialization/codec"
)

type PayloadExample struct {
	ID   int    `json:"id"`
	Data []byte `json:"data"`
}

func TestJSONSerializer(t *testing.T) {
	jsonCodec := &codec.JSONCodec[uint16]{}
	serializer := serialization.NewSerializer[uint16](jsonCodec)

	example := PayloadExample{ID: 1, Data: []byte{1, 2, 3}}

	// Test Encoding
	encoded, err := serializer.Encode(&example)
	require.NoError(t, err)
	require.NotNil(t, encoded)

	// Test Decoding
	var decoded PayloadExample
	err = serializer.Decode(encoded, &decoded)
	require.NoError(t, err)
	assert.Equal(t, example, decoded)
}

func TestSCALESerializer(t *testing.T) {
	scaleCodec := &codec.SCALECodec[uint64]{}
	serializer := serialization.NewSerializer[uint64](scaleCodec)

	example := PayloadExample{ID: 2, Data: []byte{1, 2, 3}}

	// Test Encoding
	encoded, err := serializer.Encode(example)
	require.NoError(t, err)
	require.NotNil(t, encoded)

	// Test Decoding
	var decoded PayloadExample
	err = serializer.Decode(encoded, &decoded)
	require.NoError(t, err)
	assert.Equal(t, example, decoded)
}

func TestGeneralSerializer(t *testing.T) {
	jamCodec := codec.NewJamCodec[uint64]()
	serializer := serialization.NewSerializer[uint64](jamCodec)

	// Test Encoding
	v := uint64(127)
	encoded, err := serializer.EncodeGeneral(v)
	require.NoError(t, err)
	require.Equal(t, []byte{127}, encoded)

	// Test Decoding
	var decoded uint64
	err = serializer.DecodeGeneral(encoded, &decoded)
	require.NoError(t, err)
	assert.Equal(t, v, decoded)
}

func TestTrivialSerializer(t *testing.T) {
	jamCodec := codec.NewJamCodec[uint32]()
	serializer := serialization.NewSerializer[uint32](jamCodec)

	// Test Encoding
	v := 127
	encoded, err := serializer.EncodeTrivialUint(uint32(v), 3)
	require.NoError(t, err)
	require.Equal(t, []byte{127, 0, 0}, encoded)

	// Test Decoding
	var d64 uint64
	serializer64 := serialization.NewSerializer[uint64](codec.NewJamCodec[uint64]())
	err = serializer64.DecodeTrivialUint(encoded, &d64)
	require.NoError(t, err)
	assert.Equal(t, uint64(v), d64)

	var d32 uint32
	err = serializer.DecodeTrivialUint(encoded, &d32)
	require.NoError(t, err)
	assert.Equal(t, uint32(v), d32)

	var d16 uint16
	serializer16 := serialization.NewSerializer[uint16](codec.NewJamCodec[uint16]())
	err = serializer16.DecodeTrivialUint(encoded, &d16)
	require.NoError(t, err)
	assert.Equal(t, uint16(v), d16)

	var d8 uint8
	serializer8 := serialization.NewSerializer[uint8](codec.NewJamCodec[uint8]())
	err = serializer8.DecodeTrivialUint(encoded, &d8)
	require.NoError(t, err)
	assert.Equal(t, uint8(v), d8)
}
