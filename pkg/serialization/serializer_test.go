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
	jsonCodec := &codec.JSONCodec{}
	serializer := serialization.NewSerializer(jsonCodec)

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
	scaleCodec := &codec.SCALECodec{}
	serializer := serialization.NewSerializer(scaleCodec)

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

func TestGeneralSerialization(t *testing.T) {
	jamCodec := codec.NewJamCodec()
	serializer := serialization.NewSerializer(jamCodec)

	// Test Encoding
	v := uint(127)
	encoded, err := serializer.Encode(v)
	require.NoError(t, err)
	require.Equal(t, []byte{127}, encoded)

	// Test Decoding
	var decoded uint
	err = serializer.Decode(encoded, &decoded)
	require.NoError(t, err)
	assert.Equal(t, v, decoded)
}

func TestTrivialSerialization(t *testing.T) {
	jamCodec := codec.NewJamCodec()
	serializer := serialization.NewSerializer(jamCodec)

	// Test Encoding
	v := 127
	encoded, err := serializer.Encode(uint32(v))
	require.NoError(t, err)
	require.Equal(t, []byte{127, 0, 0, 0}, encoded)

	// Test Decoding
	var d64 uint64
	err = serializer.Decode(encoded, &d64)
	require.NoError(t, err)
	assert.Equal(t, uint64(v), d64)

	var d32 uint32
	err = serializer.Decode(encoded, &d32)
	require.NoError(t, err)
	assert.Equal(t, uint32(v), d32)

	var d16 uint16
	err = serializer.Decode(encoded, &d16)
	require.NoError(t, err)
	assert.Equal(t, uint16(v), d16)

	var d8 uint8
	err = serializer.Decode(encoded, &d8)
	require.NoError(t, err)
	assert.Equal(t, uint8(v), d8)
}
