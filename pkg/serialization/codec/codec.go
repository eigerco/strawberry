package codec

type Uint interface {
	uint8 | uint16 | uint32 | uint64
}

type Codec[T Uint] interface {
	Marshal(v interface{}) ([]byte, error)
	MarshalGeneral(x uint64) ([]byte, error)
	MarshalTrivialUint(x T, l uint8) ([]byte, error)
	Unmarshal(data []byte, v interface{}) error
	UnmarshalGeneral(data []byte, v *uint64) error
	UnmarshalTrivialUint(data []byte, v *T) error
}
