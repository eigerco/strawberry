package codec

import (
	"errors"
	"github.com/eigerco/strawberry/pkg/serialization/codec/jam"
)

// JAMCodec implements the Codec interface for JSON encoding and decoding.
type JAMCodec struct {
	gn jam.GeneralNatural
}

// NewJamCodec initializes an instance of Jam codec
func NewJamCodec() *JAMCodec {
	return &JAMCodec{gn: jam.GeneralNatural{}}
}

func (j *JAMCodec) Marshal(v interface{}) ([]byte, error) {
	// TODO
	return nil, errors.New("not implemented")
}

func (j *JAMCodec) MarshalGeneral(v uint64) ([]byte, error) {
	return j.gn.SerializeUint64(v), nil
}

func (j *JAMCodec) Unmarshal(data []byte, v interface{}) error {
	// TODO
	return errors.New("not implemented")
}

func (j *JAMCodec) UnmarshalGeneral(data []byte, v *uint64) error {
	return j.gn.DeserializeUint64(data, v)
}
