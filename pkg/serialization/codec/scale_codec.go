package codec

import "github.com/ChainSafe/gossamer/pkg/scale"

// SCALECodec implements the Codec interface for SCALE encoding and decoding.
type SCALECodec[T Uint] struct{}

func (s *SCALECodec[T]) Marshal(v interface{}) ([]byte, error) {
	return scale.Marshal(v)
}

func (s *SCALECodec[T]) MarshalGeneral(v uint64) ([]byte, error) {
	return scale.Marshal(v)
}

func (s *SCALECodec[T]) MarshalTrivialUint(x T, l uint8) ([]byte, error) {
	return scale.Marshal(x)
}

func (s *SCALECodec[T]) Unmarshal(data []byte, v interface{}) error {
	return scale.Unmarshal(data, v)
}

func (s *SCALECodec[T]) UnmarshalGeneral(data []byte, v *uint64) error {
	return scale.Unmarshal(data, v)
}

func (s *SCALECodec[T]) UnmarshalTrivialUint(data []byte, x *T) error {
	return scale.Unmarshal(data, x)
}
