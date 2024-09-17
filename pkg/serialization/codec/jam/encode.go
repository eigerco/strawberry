package jam

import (
	"bytes"
	"fmt"
	"io"
	"reflect"

	"github.com/eigerco/strawberry/internal/crypto"
)

func Marshal(v interface{}) ([]byte, error) {
	buffer := bytes.NewBuffer(nil)
	es := byteWriter{
		Writer: buffer,
	}
	err := es.marshal(v)
	if err != nil {
		return nil, err
	}

	b := buffer.Bytes()

	return b, nil
}

type byteWriter struct {
	io.Writer
}

func (bw *byteWriter) marshal(in interface{}) error {
	switch in := in.(type) {
	case int:
		return bw.encodeUint(uint(in))
	case uint:
		return bw.encodeUint(in)
	case uint8, uint16, uint32, uint64:
		return bw.encodeFixedWidthUint(in)
	case []byte:
		return bw.encodeBytes(in)
	case bool:
		return bw.encodeBool(in)
	default:
		return bw.handleReflectTypes(in)
	}
}

func (bw *byteWriter) handleReflectTypes(in interface{}) error {
	val := reflect.ValueOf(in)
	switch val.Kind() {
	case reflect.Bool, reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return bw.encodeCustomPrimitive(in)
	case reflect.Ptr:
		elem := reflect.ValueOf(in).Elem()
		switch elem.IsValid() {
		case false:
			_, err := bw.Write([]byte{0})
			return err
		default:
			_, err := bw.Write([]byte{1})
			if err != nil {
				return err
			}
			return bw.marshal(elem.Interface())
		}
	case reflect.Struct:
		return bw.encodeStruct(in)
	case reflect.Array:
		return bw.encodeArray(in)
	case reflect.Slice:
		if pk, ok := in.(crypto.Ed25519PublicKey); ok {
			return bw.encodeEd25519PublicKey(pk)
		}
		return bw.encodeSlice(in)
	default:
		return fmt.Errorf(ErrUnsupportedType, in)
	}
}

func (bw *byteWriter) encodeCustomPrimitive(in interface{}) error {
	switch reflect.TypeOf(in).Kind() {
	case reflect.Bool:
		in = reflect.ValueOf(in).Convert(reflect.TypeOf(false)).Interface()
	case reflect.Int:
		in = reflect.ValueOf(in).Convert(reflect.TypeOf(int(0))).Interface()
	case reflect.Int8:
		in = reflect.ValueOf(in).Convert(reflect.TypeOf(int8(0))).Interface()
	case reflect.Int16:
		in = reflect.ValueOf(in).Convert(reflect.TypeOf(int16(0))).Interface()
	case reflect.Int32:
		in = reflect.ValueOf(in).Convert(reflect.TypeOf(int32(0))).Interface()
	case reflect.Int64:
		in = reflect.ValueOf(in).Convert(reflect.TypeOf(int64(0))).Interface()
	case reflect.Uint:
		in = reflect.ValueOf(in).Convert(reflect.TypeOf(uint(0))).Interface()
	case reflect.Uint8:
		in = reflect.ValueOf(in).Convert(reflect.TypeOf(uint8(0))).Interface()
	case reflect.Uint16:
		in = reflect.ValueOf(in).Convert(reflect.TypeOf(uint16(0))).Interface()
	case reflect.Uint32:
		in = reflect.ValueOf(in).Convert(reflect.TypeOf(uint32(0))).Interface()
	case reflect.Uint64:
		in = reflect.ValueOf(in).Convert(reflect.TypeOf(uint64(0))).Interface()
	default:
		return fmt.Errorf(ErrUnsupportedType, in)
	}

	return bw.marshal(in)
}

func (bw *byteWriter) encodeSlice(in interface{}) error {
	v := reflect.ValueOf(in)
	err := bw.encodeLength(v.Len())
	if err != nil {
		return err
	}
	for i := 0; i < v.Len(); i++ {
		err = bw.marshal(v.Index(i).Interface())
		if err != nil {
			return err
		}
	}
	return nil
}

func (bw *byteWriter) encodeArray(in interface{}) error {
	v := reflect.ValueOf(in)
	for i := 0; i < v.Len(); i++ {
		err := bw.marshal(v.Index(i).Interface())
		if err != nil {
			return err
		}
	}
	return nil
}

func (bw *byteWriter) encodeEd25519PublicKey(in crypto.Ed25519PublicKey) error {
	_, err := bw.Writer.Write(in.PublicKey)
	if err != nil {
		return err
	}

	return nil
}

func (bw *byteWriter) encodeBool(l bool) error {
	var err error
	switch l {
	case true:
		_, err = bw.Write([]byte{0x01})
	case false:
		_, err = bw.Write([]byte{0x00})
	}

	return err
}

func (bw *byteWriter) encodeBytes(b []byte) error {
	err := bw.encodeLength(len(b))
	if err != nil {
		return err
	}

	_, err = bw.Write(b)
	return err
}

func (bw *byteWriter) encodeFixedWidthUint(i interface{}) error {
	var data []byte

	switch v := i.(type) {
	case uint8:
		data = SerializeTrivialNatural(v, 1)
	case uint16:
		data = SerializeTrivialNatural(v, 2)
	case uint32:
		data = SerializeTrivialNatural(v, 4)
	case uint64:
		data = SerializeTrivialNatural(v, 8)
	default:
		return fmt.Errorf(ErrUnsupportedType, i)
	}

	_, err := bw.Write(data)
	return err
}

func (bw *byteWriter) encodeStruct(in interface{}) error {
	v := reflect.ValueOf(in)
	t := reflect.TypeOf(in)

	// Iterate over each field in the struct
	for i := 0; i < t.NumField(); i++ {
		field := v.Field(i)
		fieldType := t.Field(i)

		// Skip unexported fields
		if !field.CanInterface() {
			continue
		}

		// Marshal and encode the field value
		err := bw.marshal(field.Interface())
		if err != nil {
			return fmt.Errorf(ErrEncodingStructField, fieldType.Name, err)
		}
	}

	return nil
}

func (bw *byteWriter) encodeLength(l int) error {
	return bw.encodeUint(uint(l))
}

func (bw *byteWriter) encodeUint(i uint) error {
	encodedBytes := SerializeUint64(uint64(i))

	_, err := bw.Write(encodedBytes)

	return err
}
