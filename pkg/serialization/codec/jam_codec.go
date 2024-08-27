package codec

import (
	"github.com/eigerco/strawberry/pkg/serialization/codec/jam"
)

// JAMCodec implements the Codec interface for JAM encoding and decoding.
type JAMCodec struct {
}

// NewJamCodec initializes an instance of Jam codec
func NewJamCodec() *JAMCodec {
	return &JAMCodec{}
}

// Marshal encodes the given value
func (j *JAMCodec) Marshal(v interface{}) ([]byte, error) {
	return jam.Marshal(v)
}

// Unmarshal decodes the given byte slice into the provided value.
func (j *JAMCodec) Unmarshal(data []byte, v interface{}) error {
	return jam.Unmarshal(data, v)
}
