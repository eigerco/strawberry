package jam

import (
	"bytes"
	"crypto/ed25519"
	"fmt"
	"io"
	"math"
	"math/bits"
	"reflect"

	"github.com/eigerco/strawberry/internal/crypto"
)

func Unmarshal(data []byte, dst interface{}) error {
	dstv := reflect.ValueOf(dst)
	if dstv.Kind() != reflect.Ptr || dstv.IsNil() {
		return fmt.Errorf(ErrUnsupportedType, dst)
	}

	ds := byteReader{}
	ds.Reader = bytes.NewBuffer(data)

	return ds.unmarshal(indirect(dstv))
}

type byteReader struct {
	io.Reader
}

func (br *byteReader) unmarshal(value reflect.Value) error {
	if value.CanAddr() {
		addr := value.Addr()
		if vdt, ok := addr.Interface().(EnumType); ok {
			return br.decodeEnum(vdt)
		}
	}

	in := value.Interface()
	switch in.(type) {

	case int, uint:
		return br.decodeUint(value)
	case int8, uint8, int16, uint16, int32, uint32, int64, uint64:
		return br.decodeFixedWidthInt(value)
	case []byte:
		return br.decodeBytes(value)
	case bool:
		return br.decodeBool(value)
	default:
		return br.handleReflectTypes(value)
	}
}

func (br *byteReader) handleReflectTypes(value reflect.Value) error {
	switch value.Kind() {
	case reflect.Bool, reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return br.decodeCustomPrimitive(value)
	case reflect.Ptr:
		return br.decodePointer(value)
	case reflect.Struct:
		return br.decodeStruct(value)
	case reflect.Array:
		return br.decodeArray(value)
	case reflect.Slice:
		if value.Type() == reflect.TypeOf(ed25519.PublicKey{}) {
			return br.decodeEd25519PublicKey(value)
		}
		return br.decodeSlice(value)
	case reflect.Map:
		return br.decodeMap(value)
	default:
		return fmt.Errorf(ErrUnsupportedType, value.Interface())
	}
}

func (br *byteReader) decodeCustomPrimitive(value reflect.Value) error {
	in := value.Interface()
	inType := reflect.TypeOf(in)

	var temp reflect.Value

	switch inType.Kind() {
	case reflect.Bool:
		temp = reflect.New(reflect.TypeOf(false))
	case reflect.Int:
		temp = reflect.New(reflect.TypeOf(0))
	case reflect.Int8:
		temp = reflect.New(reflect.TypeOf(int8(0)))
	case reflect.Int16:
		temp = reflect.New(reflect.TypeOf(int16(0)))
	case reflect.Int32:
		temp = reflect.New(reflect.TypeOf(int32(0)))
	case reflect.Int64:
		temp = reflect.New(reflect.TypeOf(int64(0)))
	case reflect.Uint:
		temp = reflect.New(reflect.TypeOf(uint(0)))
	case reflect.Uint8:
		temp = reflect.New(reflect.TypeOf(uint8(0)))
	case reflect.Uint16:
		temp = reflect.New(reflect.TypeOf(uint16(0)))
	case reflect.Uint32:
		temp = reflect.New(reflect.TypeOf(uint32(0)))
	case reflect.Uint64:
		temp = reflect.New(reflect.TypeOf(uint64(0)))
	default:
		return fmt.Errorf(ErrUnsupportedType, in)
	}

	if err := br.unmarshal(temp.Elem()); err != nil {
		return err
	}

	value.Set(temp.Elem().Convert(inType))

	return nil
}

func (br *byteReader) ReadOctet() (byte, error) {
	var b [1]byte
	_, err := br.Reader.Read(b[:])
	if err != nil {
		return 0, err
	}
	return b[0], nil
}

func (br *byteReader) decodeEnum(enum EnumType) error {
	b, err := br.ReadOctet()
	if err != nil {
		return err
	}

	val, err := enum.ValueAt(uint(b))
	if err != nil {
		return err
	}

	if val == nil {
		return enum.SetValue(b)
	}

	tempVal := reflect.New(reflect.TypeOf(val))
	tempVal.Elem().Set(reflect.ValueOf(val))

	err = br.unmarshal(tempVal.Elem())

	if err != nil {
		return err
	}

	return enum.SetValue(tempVal.Elem().Interface())
}

func (br *byteReader) decodePointer(value reflect.Value) error {
	rb, err := br.ReadOctet()
	if err != nil {
		return err
	}

	switch rb {
	case 0x00:
		// Handle the nil pointer case by setting the destination to nil if necessary
		if !value.IsNil() {
			value.Set(reflect.Zero(value.Type()))
		}
	case 0x01:
		// Check if the destination is a non-nil pointer
		if !value.IsZero() {
			// If it's a pointer to another pointer, we need to handle it recursively
			if value.Elem().Kind() == reflect.Ptr {
				return br.unmarshal(value.Elem().Elem())
			}
			return br.unmarshal(value.Elem())
		}

		// If value is nil or zero, we need to create a new instance
		elemType := value.Type().Elem()
		tempElem := reflect.New(elemType)
		if err := br.unmarshal(tempElem.Elem()); err != nil {
			return err
		}
		value.Set(tempElem)
	default:
		return ErrInvalidPointer
	}
	return nil
}

func (br *byteReader) decodeSlice(value reflect.Value) error {
	l, err := br.decodeLength()
	if err != nil {
		return err
	}
	in := value.Interface()
	temp := reflect.New(reflect.ValueOf(in).Type())
	for i := uint(0); i < l; i++ {
		tempElemType := reflect.TypeOf(in).Elem()
		tempElem := reflect.New(tempElemType).Elem()

		err = br.unmarshal(tempElem)
		if err != nil {
			return err
		}
		temp.Elem().Set(reflect.Append(temp.Elem(), tempElem))
	}
	value.Set(temp.Elem())

	return nil
}

func (br *byteReader) decodeArray(value reflect.Value) error {
	in := value.Interface()
	temp := reflect.New(reflect.ValueOf(in).Type())
	for i := 0; i < temp.Elem().Len(); i++ {
		elem := temp.Elem().Index(i)
		err := br.unmarshal(elem)
		if err != nil {
			return err
		}
	}
	value.Set(temp.Elem())

	return nil
}

func (br *byteReader) decodeMap(value reflect.Value) error {
	// Get the type of the map's key and value
	mapType := value.Type()
	keyType := mapType.Key()
	elemType := mapType.Elem()

	// Decode the length of the map (i.e., the number of key-value pairs)
	length, err := br.decodeLength()
	if err != nil {
		return fmt.Errorf(ErrDecodingMapLength, err)
	}

	// Create a new map of the appropriate type and capacity
	tempMap := reflect.MakeMapWithSize(mapType, int(length))

	// Loop over the number of key-value pairs
	for i := uint(0); i < length; i++ {
		// Decode the key
		key := reflect.New(keyType).Elem() // Create a new key of the map's key type
		if err := br.unmarshal(key); err != nil {
			return fmt.Errorf(ErrDecodingMapKey, err)
		}

		// Decode the value
		value := reflect.New(elemType).Elem() // Create a new value of the map's element type
		if err := br.unmarshal(value); err != nil {
			return fmt.Errorf(ErrDecodingMapValue, err)
		}

		// Insert the key-value pair into the temporary map
		tempMap.SetMapIndex(key, value)
	}

	// Set the decoded map into the destination value
	value.Set(tempMap)

	return nil
}

func (br *byteReader) decodeEd25519PublicKey(value reflect.Value) error {
	publicKey := ed25519.PublicKey(make([]byte, crypto.Ed25519PublicSize))
	if _, err := io.ReadFull(br.Reader, publicKey); err != nil {
		return err
	}

	value.Set(reflect.ValueOf(publicKey))

	return nil
}

func (br *byteReader) decodeStruct(value reflect.Value) error {
	t := value.Type()

	// Iterate over each field in the struct
	for i := 0; i < value.NumField(); i++ {
		field := value.Field(i)
		fieldType := t.Field(i)

		// Skip unexported fields
		if !field.CanSet() {
			continue
		}
		if tag, ok := fieldType.Tag.Lookup("jam"); ok {
			if tag == "-" {
				continue
			}
		}

		// Decode the field value
		err := br.unmarshal(field)
		if err != nil {
			return fmt.Errorf(ErrDecodingStructField, fieldType.Name, err)
		}
	}

	return nil
}

func (br *byteReader) decodeBool(value reflect.Value) error {
	rb, err := br.ReadOctet()
	if err != nil {
		return err
	}

	switch rb {
	case 0x00:
		value.SetBool(false)
	case 0x01:
		value.SetBool(true)
	default:
		return ErrDecodingBool
	}

	return nil
}

func (br *byteReader) decodeUint(value reflect.Value) error {
	// Read the first byte to determine how many bytes are used in the encoding
	prefix, err := br.ReadOctet()
	if err != nil {
		return fmt.Errorf(ErrReadingByte, err)
	}

	var serialized []byte

	// Determine the number of additional bytes using the prefix
	l := uint8(bits.LeadingZeros8(^prefix))

	serialized = make([]byte, l+1)
	serialized[0] = prefix
	_, err = br.Read(serialized[1:])
	if err != nil {
		return fmt.Errorf(ErrReadingBytes, err)
	}

	var v uint64
	err = DeserializeUint64WithLength(serialized, l, &v)
	if err != nil {
		return fmt.Errorf(ErrDecodingUint, err)
	}

	// Set the decoded value into the destination
	value.Set(reflect.ValueOf(v).Convert(value.Type()))

	return nil
}

// decodeLength is helper method which calls decodeUint and casts to int
func (br *byteReader) decodeLength() (uint, error) {
	var l uint
	dstv := reflect.New(reflect.TypeOf(l))
	err := br.decodeUint(dstv.Elem())
	if err != nil {
		return 0, fmt.Errorf(ErrDecodingUint, err)
	}
	l = dstv.Elem().Interface().(uint)
	return l, nil
}

// decodeBytes is used to decode with a destination of []byte
func (br *byteReader) decodeBytes(dstv reflect.Value) error {
	length, err := br.decodeLength()
	if err != nil {
		return err
	}

	if length > math.MaxUint32 {
		return ErrExceedingByteArrayLimit
	}

	b := make([]byte, length)

	if length > 0 {
		_, err = br.Read(b)
		if err != nil {
			return err
		}
	}

	in := dstv.Interface()
	inType := reflect.TypeOf(in)
	dstv.Set(reflect.ValueOf(b).Convert(inType))
	return nil
}

func (br *byteReader) decodeFixedWidthInt(dstv reflect.Value) error {
	in := dstv.Interface()
	var buf []byte
	var length int

	switch in.(type) {
	case uint8:
		length = 1
	case uint16:
		length = 2
	case uint32:
		length = 4
	case uint64:
		length = 8
	default:
		return fmt.Errorf(ErrUnsupportedType, in)
	}

	// Read the appropriate number of bytes
	buf = make([]byte, length)
	_, err := br.Read(buf)
	if err != nil {
		return fmt.Errorf(ErrReadingByte, err)
	}

	// Deserialize the value
	switch in.(type) {
	case uint8:
		var temp uint8
		DeserializeTrivialNatural(buf, &temp)
		dstv.Set(reflect.ValueOf(temp))
	case uint16:
		var temp uint16
		DeserializeTrivialNatural(buf, &temp)
		dstv.Set(reflect.ValueOf(temp))
	case uint32:
		var temp uint32
		DeserializeTrivialNatural(buf, &temp)
		dstv.Set(reflect.ValueOf(temp))
	case uint64:
		var temp uint64
		DeserializeTrivialNatural(buf, &temp)
		dstv.Set(reflect.ValueOf(temp))
	}

	return nil
}

// indirect recursively dereferences pointers and interfaces,
// allocating new pointers as needed, until it reaches a non-pointer value.
func indirect(v reflect.Value) reflect.Value {
	for {
		switch v.Kind() {
		case reflect.Ptr:
			if v.IsNil() {
				v.Set(reflect.New(v.Type().Elem()))
			}
			v = v.Elem()
		case reflect.Interface:
			if v.IsNil() {
				return v
			}
			v = v.Elem()
		default:
			return v
		}
	}
}
