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