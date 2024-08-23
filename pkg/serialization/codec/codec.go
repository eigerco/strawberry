package codec

type Uint interface {
	uint8 | uint16 | uint32 | uint64
}

type Codec interface {
	Marshal(v interface{}) ([]byte, error)
	Unmarshal(data []byte, v interface{}) error
}
