package codec

import (
	"encoding/json"
)

// JSONCodec implements the Codec interface for JSON encoding and decoding.
type JSONCodec[T Uint] struct{}

func (j *JSONCodec[T]) Marshal(v interface{}) ([]byte, error) {
	return json.Marshal(v)
}

func (j *JSONCodec[T]) MarshalGeneral(v uint64) ([]byte, error) {
	return json.Marshal(v)
}

func (j *JSONCodec[T]) MarshalTrivialUint(x T, l uint8) ([]byte, error) {
	return json.Marshal(x)
}

func (j *JSONCodec[T]) Unmarshal(data []byte, v interface{}) error {
	return json.Unmarshal(data, v)
}

func (j *JSONCodec[T]) UnmarshalGeneral(data []byte, v *uint64) error {
	return json.Unmarshal(data, v)
}

func (j *JSONCodec[T]) UnmarshalTrivialUint(data []byte, x *T) error {
	return json.Unmarshal(data, x)
}
