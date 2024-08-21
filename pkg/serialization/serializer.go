package serialization

import "github.com/eigerco/strawberry/pkg/serialization/codec"

// Serializer provides methods to encode and decode using a specified codec.
type Serializer[T codec.Uint] struct {
	codec codec.Codec[T]
}

// NewSerializer initializes a new Serializer with the given codec.
func NewSerializer[T codec.Uint](c codec.Codec[T]) *Serializer[T] {
	return &Serializer[T]{codec: c}
}

// Encode serializes the given value using the codec.
func (s *Serializer[T]) Encode(v interface{}) ([]byte, error) {
	return s.codec.Marshal(v)
}

// EncodeGeneral is specific encoding for natural numbers up to 2^64
func (s *Serializer[T]) EncodeGeneral(v uint64) ([]byte, error) {
	return s.codec.MarshalGeneral(v)
}

// EncodeTrivialUint is the trivial encoding for natural numbers
func (s *Serializer[T]) EncodeTrivialUint(x T, l uint8) ([]byte, error) {
	return s.codec.MarshalTrivialUint(x, l)
}

// Decode deserializes the given data into the specified value using the codec.
func (s *Serializer[T]) Decode(data []byte, v interface{}) error {
	return s.codec.Unmarshal(data, v)
}

// DecodeGeneral is specific decoding for natural numbers up to 2^64
func (s *Serializer[T]) DecodeGeneral(data []byte, v *uint64) error {
	return s.codec.UnmarshalGeneral(data, v)
}

// DecodeTrivialUint is the trivial decoding for natural numbers
func (s *Serializer[T]) DecodeTrivialUint(data []byte, v *T) error {
	return s.codec.UnmarshalTrivialUint(data, v)
}
