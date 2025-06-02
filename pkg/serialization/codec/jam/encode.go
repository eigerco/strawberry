package jam

import (
	"bytes"
	"crypto/ed25519"
	"fmt"
	"io"
	"reflect"
	"sort"
	"strconv"
)

// Marshaler is the interface implemented by types that can marshal themselves
// into valid JAM encoded data.
type Marshaler interface {
	MarshalJAM() ([]byte, error)
}

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
	// Check if the input implements the Marshaler interface and do custom
	// encoding in that case.
	marshaler, ok := in.(Marshaler)
	if ok {
		b, err := marshaler.MarshalJAM()
		if err != nil {
			return err
		}
		_, err = bw.Write(b)
		return err
	}

	if v, ok := in.(EncodeEnum); ok {
		return bw.encodeEnumType(v)
	}

	switch v := in.(type) {
	case int:
		return bw.encodeCompact(uint64(v))
	case uint:
		return bw.encodeCompact(uint64(v))
	case uint8, uint16, uint32, uint64:
		l, err := IntLength(v)
		if err != nil {
			return err
		}
		return bw.encodeFixedWidth(v, l)
	case []byte:
		return bw.encodeBytes(v)
	case BitSequence:
		return bw.encodeBits(v)
	case bool:
		return bw.encodeBool(v)
	default:
		return bw.handleReflectTypes(v)
	}
}

func (bw *byteWriter) handleReflectTypes(in interface{}) error {
	val := reflect.ValueOf(in)
	switch val.Kind() {
	case reflect.Bool, reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return bw.encodeCustomPrimitive(in)
	case reflect.Ptr:
		err := bw.writePointerMarker(val.IsNil())
		if err != nil {
			return err
		}
		if val.IsNil() {
			return nil
		}
		return bw.marshal(val.Elem().Interface())
	case reflect.Struct:
		return bw.encodeStruct(in)
	case reflect.Array:
		return bw.encodeArray(in)
	case reflect.Slice:
		switch v := in.(type) {
		case ed25519.PublicKey:
			return bw.encodeEd25519PublicKey(v)
		case BitSequence:
			return bw.encodeBits(v)
		case []byte:
			return bw.encodeBytes(v)
		default:
			return bw.encodeSlice(in)
		}
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

func (bw *byteWriter) encodeBits(bitSequence BitSequence) error {
	length := len(bitSequence) / 8
	if len(bitSequence) > 0 && length%8 == 0 {
		length += 1
	}
	err := bw.encodeLength(length)
	if err != nil {
		return err
	}

	bb := make([]byte, length)
	for i, b := range bitSequence {
		if b {
			pow2 := byte(1 << (i % 8)) // powers of 2
			bb[i/8] |= pow2            // identify the bit
		}
	}

	_, err = bw.Write(bb)
	return err
}

func (bw *byteWriter) encodeFixedWidth(i interface{}, l uint) error {
	val := reflect.ValueOf(i)

	// Handle pointers
	if val.Kind() == reflect.Ptr {
		err := bw.writePointerMarker(val.IsNil())
		if err != nil {
			return err
		}
		if val.IsNil() {
			return nil
		}
		val = val.Elem() // Dereference non-nil pointer
	}

	typ := val.Type()
	switch typ.Kind() {
	case reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uint:
		data := serializeTrivialNatural(val.Uint(), l)
		_, err := bw.Write(data)
		return err
	default:
		return fmt.Errorf(ErrUnsupportedType, i)
	}
}

func (bw *byteWriter) writePointerMarker(isNil bool) error {
	marker := byte(0x00)
	if !isNil {
		marker = byte(0x01)
	}
	_, err := bw.Write([]byte{marker})
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

			tagValues := parseTag(tag)
			encodingType, encodingTagFound := tagValues["encoding"]
			if length, found := tagValues["length"]; found {
				// "length" and "encoding" are mutually exclusive
				if encodingTagFound {
					return fmt.Errorf(ErrConflictingTags, fieldType.Name)
				}

				size, err := strconv.ParseUint(length, 10, 64)
				if err != nil {
					return fmt.Errorf(ErrInvalidLengthValue, fieldType.Name, err)
				}

				err = bw.encodeFixedWidth(field.Interface(), uint(size))
				if err != nil {
					return fmt.Errorf(ErrEncodingStructField, fieldType.Name, err)
				}
				continue
			}
			// Handle compact encoding for unsigned integers if specified via struct tag
			if encodingTagFound && encodingType == "compact" {
				switch field.Kind() {
				case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
					err := bw.encodeCompact(field.Uint())
					if err != nil {
						return fmt.Errorf(ErrEncodingStructField, fieldType.Name, err)
					}
					continue
				default:
					return fmt.Errorf(ErrUnSuportedFieldForCompactEncoding, field.Kind())
				}
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
	return bw.encodeCompact(uint64(l))
}

// encodeCompact encodes an uint64 using the general compact natural number encoding
// as defined in appendix C.6. This encoding produces a variable-length
// byte sequence (1–9 bytes) depending on the input
func (bw *byteWriter) encodeCompact(i uint64) error {
	encodedBytes := serializeUint64(i)

	_, err := bw.Write(encodedBytes)

	return err
}
