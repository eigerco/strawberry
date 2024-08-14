package codec

import "github.com/ChainSafe/gossamer/pkg/scale"

// SCALECodec implements the Codec interface for SCALE encoding and decoding.
type SCALECodec struct{}

func (s *SCALECodec) Marshal(v interface{}) ([]byte, error) {
	return scale.Marshal(v)
}

func (j *SCALECodec) MarshalGeneral(v uint64) ([]byte, error) {
	return scale.Marshal(v)
}

func (s *SCALECodec) Unmarshal(data []byte, v interface{}) error {
	return scale.Unmarshal(data, v)
}

func (s *SCALECodec) UnmarshalGeneral(data []byte, v *uint64) error {
	return scale.Unmarshal(data, v)
}
