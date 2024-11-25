package jam

import (
	"bytes"
	"crypto/ed25519"
	"fmt"
	"io"
	"reflect"
	"sort"
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
	if v, ok := in.(EncodeEnum); ok {
		return bw.encodeEnumType(v)
	}

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
		if pk, ok := in.(ed25519.PublicKey); ok {
			return bw.encodeEd25519PublicKey(pk)
		}
		return bw.encodeSlice(in)
	case reflect.Map:
		return bw.encodeMap(in)
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

func (bw *byteWriter) encodeEnumType(enum EncodeEnum) error {
	index, value, err := enum.IndexValue()
	if err != nil {
		return err
	}

	_, err = bw.Write([]byte{byte(index)})
	if err != nil {
		return err
	}

	if value == nil {
		return nil
	}

	return bw.marshal(value)
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

func (bw *byteWriter) encodeEd25519PublicKey(in ed25519.PublicKey) error {
	_, err := bw.Writer.Write(in)
	if err != nil {
		return err
	}

	return nil
}

// encodeMap encodes a map, sorting the keys based on their type
func (bw *byteWriter) encodeMap(in interface{}) error {
	// Ensure that input is a map
	v := reflect.ValueOf(in)
	if v.Kind() != reflect.Map {
		return fmt.Errorf(ErrUnsupportedType, in)
	}

	// Get the map keys
	keys := v.MapKeys()

	// If the map is empty, just encode the length (0)
	if len(keys) == 0 {
		return bw.encodeLength(0)
	}

	// Sort keys based on their type
	if err := bw.sortMapKeys(keys); err != nil {
		return err
	}

	// Encode the number of key-value pairs
	if err := bw.encodeLength(len(keys)); err != nil {
		return err
	}

	// Encode each key and corresponding value
	for _, key := range keys {
		// Marshal the key
		if err := bw.marshal(key.Interface()); err != nil {
			return err
		}

		// Marshal the value associated with the key
		value := v.MapIndex(key)
		if err := bw.marshal(value.Interface()); err != nil {
			return err
		}
	}

	return nil
}

// sortMapKeys sorts map keys based on their type
func (bw *byteWriter) sortMapKeys(keys []reflect.Value) error {
	// Sort based on the key type
	switch keys[0].Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		sort.Slice(keys, func(i, j int) bool {
			return keys[i].Int() < keys[j].Int()
		})
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		sort.Slice(keys, func(i, j int) bool {
			return keys[i].Uint() < keys[j].Uint()
		})
	case reflect.Float32, reflect.Float64:
		sort.Slice(keys, func(i, j int) bool {
			return keys[i].Float() < keys[j].Float()
		})
	case reflect.Bool:
		// Sort bools: false comes before true
		sort.Slice(keys, func(i, j int) bool {
			return !keys[i].Bool() && keys[j].Bool()
		})
	case reflect.Array:
		// Check if the array is a byte array ([N]byte)
		if keys[0].Type().Elem().Kind() == reflect.Uint8 {
			sort.Slice(keys, func(i, j int) bool {
				return compareByteArrays(keys[i], keys[j])
			})
		} else {
			return fmt.Errorf("unsupported array type: %v", keys[0].Type())
		}
	default:
		return fmt.Errorf(ErrEncodingMapFieldKeyType, keys[0].Kind())
	}

	return nil
}

// compareByteArrays compares two reflect.Value arrays (assumed to be byte arrays) lexicographically
func compareByteArrays(a, b reflect.Value) bool {
	// Convert reflect.Value arrays to byte slices
	aBytes := reflectToByteSlice(a)
	bBytes := reflectToByteSlice(b)
	return bytes.Compare(aBytes, bBytes) < 0
}

// reflectToByteSlice converts a reflect.Value of an array (e.g., [32]byte) to a []byte
func reflectToByteSlice(v reflect.Value) []byte {
	byteSlice := make([]byte, v.Len())
	for i := 0; i < v.Len(); i++ {
		byteSlice[i] = byte(v.Index(i).Uint()) // Convert each element to a byte
	}
	return byteSlice
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
		data = serializeTrivialNatural(v, 1)
	case uint16:
		data = serializeTrivialNatural(v, 2)
	case uint32:
		data = serializeTrivialNatural(v, 4)
	case uint64:
		data = serializeTrivialNatural(v, 8)
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
		if tag, ok := fieldType.Tag.Lookup("jam"); ok {
			if tag == "-" {
				continue
			}
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
	encodedBytes := serializeUint64(uint64(i))

	_, err := bw.Write(encodedBytes)

	return err
}
