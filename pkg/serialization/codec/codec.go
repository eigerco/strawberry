package codec

type Codec interface {
	Marshal(v interface{}) ([]byte, error)
	MarshalGeneral(x uint64) ([]byte, error)
	MarshalTrivialUint(x interface{}, l uint8) ([]byte, error)
	Unmarshal(data []byte, v interface{}) error
	UnmarshalGeneral(data []byte, v *uint64) error
	UnmarshalTrivialUint(data []byte, v interface{}) error
}
