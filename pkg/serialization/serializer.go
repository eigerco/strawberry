package serialization

import "github.com/eigerco/strawberry/pkg/serialization/codec"

// Serializer provides methods to encode and decode using a specified codec.
type Serializer struct {
	codec codec.Codec
}

// NewSerializer initializes a new Serializer with the given codec.
func NewSerializer(c codec.Codec) *Serializer {
	return &Serializer{codec: c}
}

// Encode serializes the given value using the codec.
func (s *Serializer) Encode(v interface{}) ([]byte, error) {
	return s.codec.Marshal(v)
}

// Decode deserializes the given data into the specified value using the codec.
func (s *Serializer) Decode(data []byte, v interface{}) error {
	return s.codec.Unmarshal(data, v)
}
