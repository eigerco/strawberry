package codec

import (
	"fmt"
	"reflect"

	"github.com/eigerco/strawberry/pkg/serialization/codec/jam"
)

// JAMCodec implements the Codec interface for JSON encoding and decoding.
type JAMCodec[T Uint] struct {
	gn jam.GeneralNatural
}

// NewJamCodec initializes an instance of Jam codec
func NewJamCodec[T Uint]() *JAMCodec[T] {
	return &JAMCodec[T]{
		gn: jam.GeneralNatural{},
	}
}

// Marshal encodes the given value into a byte slice.
func (j *JAMCodec[T]) Marshal(v interface{}) ([]byte, error) {
	val := reflect.ValueOf(v)

	switch val.Kind() {
	case reflect.Bool:
		return j.encodeBool(val.Bool())
	case reflect.Array, reflect.Slice:
		if val.Type().Elem().Kind() == reflect.Uint8 {
			return j.encodeByteSlice(val)
		}
	}

	return nil, fmt.Errorf(jam.ErrUnsupportedType, v)
}

// Unmarshal decodes the given byte slice into the provided value.
func (j *JAMCodec[T]) Unmarshal(data []byte, v interface{}) error {
	if len(data) == 0 {
		return jam.ErrEmptyData
	}

	val := reflect.ValueOf(v)
	if val.Kind() != reflect.Ptr || val.IsNil() {
		return jam.ErrNonPointerOrNil
	}

	elem := val.Elem()

	switch elem.Kind() {
	case reflect.Bool:
		return j.decodeBool(data, elem)
	case reflect.Slice, reflect.Array:
		if elem.Type().Elem().Kind() == reflect.Uint8 {
			return j.decodeByteSlice(data, elem)
		}
	}

	return fmt.Errorf(jam.ErrUnsupportedType, v)
}

func (j *JAMCodec[T]) MarshalGeneral(v uint64) ([]byte, error) {
	return j.gn.SerializeUint64(v), nil
}

func (j *JAMCodec[T]) MarshalTrivialUint(x T, l uint8) ([]byte, error) {
	return jam.SerializeTrivialNatural(x, l), nil
}

func (j *JAMCodec[T]) UnmarshalGeneral(data []byte, v *uint64) error {
	return j.gn.DeserializeUint64(data, v)
}

func (j *JAMCodec[T]) UnmarshalTrivialUint(data []byte, x *T) error {
	jam.DeserializeTrivialNatural(data, x)
	return nil
}

// encodeBool encodes a boolean value into a byte slice.
func (j *JAMCodec[T]) encodeBool(b bool) ([]byte, error) {
	if b {
		return []byte{0x01}, nil // true -> 0x01
	}
	return []byte{0x00}, nil // false -> 0x00
}

// decodeBool decodes a boolean value from a byte slice.
func (j *JAMCodec[T]) decodeBool(data []byte, elem reflect.Value) error {
	if len(data) == 0 {
		return jam.ErrEmptyData
	}

	switch data[0] {
	case 0x01:
		elem.SetBool(true)
	case 0x00:
		elem.SetBool(false)
	default:
		return jam.ErrInvalidBooleanEncoding
	}
	return nil
}

// encodeByteSlice encodes a byte slice or array into a byte slice with a serialized length.
func (j *JAMCodec[T]) encodeByteSlice(val reflect.Value) ([]byte, error) {
	byteSlice, err := j.toByteSlice(val)
	if err != nil {
		return nil, err
	}

	// Serialize the length using SerializeUint64
	lengthBytes := j.gn.SerializeUint64(uint64(len(byteSlice)))

	// Prepend the serialized length to the byte slice
	result := append(lengthBytes, byteSlice...)
	return result, nil
}

// decodeByteSlice decodes a byte slice or array from the given byte slice.
func (j *JAMCodec[T]) decodeByteSlice(data []byte, elem reflect.Value) error {
	// Deserialize the length using the first part of the data
	var length uint64
	err := j.gn.DeserializeUint64(data, &length)
	if err != nil {
		return err
	}

	// Calculate how many bytes were used to represent the length
	lengthBytesCount := len(j.gn.SerializeUint64(length))

	// Check if the remaining data has the expected length
	if len(data)-lengthBytesCount < int(length) {
		return fmt.Errorf(jam.ErrDataLengthMismatch, length, len(data)-lengthBytesCount)
	}

	// Extract the actual data based on the deserialized length
	extractedData := data[lengthBytesCount : lengthBytesCount+int(length)]

	if elem.Kind() == reflect.Slice {
		elem.SetBytes(extractedData)
	} else if elem.Kind() == reflect.Array {
		if elem.Len() != len(extractedData) {
			return fmt.Errorf(jam.ErrArrayLengthMismatch, elem.Len(), len(extractedData))
		}
		reflect.Copy(elem, reflect.ValueOf(extractedData))
	}

	return nil
}

// toByteSlice converts an array or slice of bytes to a byte slice.
func (j *JAMCodec[T]) toByteSlice(val reflect.Value) ([]byte, error) {
	switch val.Kind() {
	case reflect.Array:
		b := make([]byte, val.Len())
		reflect.Copy(reflect.ValueOf(b), val)
		return b, nil
	case reflect.Slice:
		return val.Interface().([]byte), nil
	default:
		return nil, fmt.Errorf(jam.ErrUnsupportedType, val.Kind())
	}
}
