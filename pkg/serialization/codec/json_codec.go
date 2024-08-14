package codec

import (
	"encoding/json"
)

// JSONCodec implements the Codec interface for JSON encoding and decoding.
type JSONCodec struct{}

func (j *JSONCodec) Marshal(v interface{}) ([]byte, error) {
	return json.Marshal(v)
}

func (j *JSONCodec) MarshalGeneral(v uint64) ([]byte, error) {
	return json.Marshal(v)
}

func (j *JSONCodec) MarshalTrivialUint(x interface{}, l uint8) ([]byte, error) {
	return json.Marshal(x)
}

func (j *JSONCodec) Unmarshal(data []byte, v interface{}) error {
	return json.Unmarshal(data, v)
}

func (j *JSONCodec) UnmarshalGeneral(data []byte, v *uint64) error {
	return json.Unmarshal(data, v)
}

func (j *JSONCodec) UnmarshalTrivialUint(data []byte, x interface{}) error {
	return json.Unmarshal(data, x)
}
