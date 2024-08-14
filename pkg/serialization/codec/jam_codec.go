package codec

import (
	"errors"
	"fmt"
	"github.com/eigerco/strawberry/pkg/serialization/codec/jam"
)

var unsupportedType = "unsupported type: %T"

// JAMCodec implements the Codec interface for JSON encoding and decoding.
type JAMCodec struct {
	gn   jam.GeneralNatural
	tn8  jam.TrivialNatural[uint8]
	tn16 jam.TrivialNatural[uint16]
	tn32 jam.TrivialNatural[uint32]
	tn64 jam.TrivialNatural[uint64]
}

// NewJamCodec initializes an instance of Jam codec
func NewJamCodec() *JAMCodec {
	return &JAMCodec{
		gn:   jam.GeneralNatural{},
		tn8:  jam.TrivialNatural[uint8]{},
		tn16: jam.TrivialNatural[uint16]{},
		tn32: jam.TrivialNatural[uint32]{},
		tn64: jam.TrivialNatural[uint64]{},
	}
}

func (j *JAMCodec) Marshal(v interface{}) ([]byte, error) {
	// TODO
	return nil, errors.New("not implemented")
}

func (j *JAMCodec) MarshalGeneral(v uint64) ([]byte, error) {
	return j.gn.SerializeUint64(v), nil
}

func (j *JAMCodec) MarshalTrivialUint(x interface{}, l uint8) ([]byte, error) {
	switch v := x.(type) {
	case uint8:
		return j.tn8.Serialize(v, l), nil
	case uint16:
		return j.tn16.Serialize(v, l), nil
	case uint32:
		return j.tn32.Serialize(v, l), nil
	case uint64:
		return j.tn64.Serialize(v, l), nil
	default:
		return nil, fmt.Errorf(unsupportedType, v)
	}
}

func (j *JAMCodec) Unmarshal(data []byte, v interface{}) error {
	// TODO
	return errors.New("not implemented")
}

func (j *JAMCodec) UnmarshalGeneral(data []byte, v *uint64) error {
	return j.gn.DeserializeUint64(data, v)
}

func (j *JAMCodec) UnmarshalTrivialUint(data []byte, x interface{}) error {
	switch v := x.(type) {
	case *uint8:
		return j.tn8.Deserialize(data, v)
	case *uint16:
		return j.tn16.Deserialize(data, v)
	case *uint32:
		return j.tn32.Deserialize(data, v)
	case *uint64:
		return j.tn64.Deserialize(data, v)
	default:
		return fmt.Errorf(unsupportedType, v)
	}
}
