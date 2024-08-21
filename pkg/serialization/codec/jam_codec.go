package codec

import (
	"errors"
	"github.com/eigerco/strawberry/pkg/serialization/codec/jam"
)

// JAMCodec implements the Codec interface for JSON encoding and decoding.
type JAMCodec[T Uint] struct {
	gn jam.GeneralNatural
}

// NewJamCodec initializes an instance of Jam codec
func NewJamCodec[T Uint]() *JAMCodec[T] {
	return &JAMCodec[T]{
		gn: jam.GeneralNatural{},
	}
}

func (j *JAMCodec[T]) Marshal(v interface{}) ([]byte, error) {
	// TODO
	return nil, errors.New("not implemented")
}

func (j *JAMCodec[T]) MarshalGeneral(v uint64) ([]byte, error) {
	return j.gn.SerializeUint64(v), nil
}

func (j *JAMCodec[T]) MarshalTrivialUint(x T, l uint8) ([]byte, error) {
	return jam.SerializeTrivialNatural(x, l), nil
}

func (j *JAMCodec[T]) Unmarshal(data []byte, v interface{}) error {
	// TODO
	return errors.New("not implemented")
}

func (j *JAMCodec[T]) UnmarshalGeneral(data []byte, v *uint64) error {
	return j.gn.DeserializeUint64(data, v)
}

func (j *JAMCodec[T]) UnmarshalTrivialUint(data []byte, x *T) error {
	jam.DeserializeTrivialNatural(data, x)
	return nil
}
