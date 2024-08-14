package codec

type Codec interface {
	Marshal(v interface{}) ([]byte, error)
	MarshalGeneral(x uint64) ([]byte, error)
	Unmarshal(data []byte, v interface{}) error
	UnmarshalGeneral(data []byte, v *uint64) error
}
