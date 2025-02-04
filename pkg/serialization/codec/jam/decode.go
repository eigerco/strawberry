package jam

import (
	"bytes"
	"crypto/ed25519"
	"fmt"
	"io"
	"math"
	"math/bits"
	"reflect"
	"strconv"

	"github.com/eigerco/strawberry/internal/crypto"
)

type BitSequence []bool

func Unmarshal(data []byte, dst interface{}) error {
	dstv := reflect.ValueOf(dst)
	if dstv.Kind() != reflect.Ptr || dstv.IsNil() {
		return fmt.Errorf(ErrUnsupportedType, dst)
	}

	ds := byteReader{}
	ds.Reader = bytes.NewBuffer(data)

	return ds.unmarshal(indirect(dstv))
}

func NewDecoder(reader io.Reader) *Decoder {
	return &Decoder{
		byteReader{reader},
	}
}

type Decoder struct {
	byteReader
}

func (d *Decoder) Decode(dst any) error {
	dstv := reflect.ValueOf(dst)
	if dstv.Kind() != reflect.Ptr || dstv.IsNil() {
		return fmt.Errorf(ErrUnsupportedType, dst)
	}

	return d.unmarshal(indirect(dstv))
}

func (d *Decoder) DecodeFixedLength(dst any, length uint) error {
	dstv := reflect.ValueOf(dst)
	if dstv.Kind() != reflect.Ptr || dstv.IsNil() {
		return fmt.Errorf(ErrUnsupportedType, dst)
	}
	dstv = indirect(dstv)

	in := dstv.Interface()
	switch v := in.(type) {
	case int8, uint8, int16, uint16, int32, uint32, int64, uint64:
		return d.decodeFixedWidth(dstv, length)
	case []byte:
		return d.decodeBytesFixedLength(dstv, length)
	case BitSequence:
		if err := d.decodeBitsFixedLength(&v, length); err != nil {
			return err
		}
		inType := reflect.TypeOf(in)
		dstv.Set(reflect.ValueOf(v).Convert(inType))
	default:
		return fmt.Errorf(ErrUnsupportedType, dst)
	}
	return nil
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
		l, err := IntLength(value.Interface())
		if err != nil {
			return err
		}
		return br.decodeFixedWidth(value, l)
	case []byte:
		return br.decodeBytes(value)
	case BitSequence:
		return br.decodeBits(value)
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
		if value.Type() == reflect.TypeOf(BitSequence{}) {
			return br.decodeBits(value)
		}
		if value.Type() == reflect.TypeOf([]byte{}) {
			return br.decodeBytes(value)
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
	isNil, err := br.readPointerMarker()
	if err != nil {
		return err
	}

	if isNil {
		// Set the pointer to nil
		if !value.IsNil() {
			value.Set(reflect.Zero(value.Type()))
		}
		return nil
	}

	// Allocate space for the pointer if it's nil
	if value.IsNil() {
		value.Set(reflect.New(value.Type().Elem()))
	}

	// Decode the dereferenced value
	return br.unmarshal(value.Elem())
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
			tagValues := parseTag(tag)
			if length, found := tagValues["length"]; found {
				size, err := strconv.ParseUint(length, 10, 64)
				if err != nil {
					return fmt.Errorf(ErrInvalidLengthValue, fieldType.Name, err)
				}

				err = br.decodeFixedWidth(field, uint(size))
				if err != nil {
					return fmt.Errorf(ErrEncodingStructField, fieldType.Name, err)
				}
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
	err = deserializeUint64WithLength(serialized, l, &v)
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
	return br.decodeBytesFixedLength(dstv, length)
}

// decodeBytes is used to decode with a destination of []byte
func (br *byteReader) decodeBytesFixedLength(dstv reflect.Value, length uint) error {
	if length > math.MaxUint32 {
		return ErrExceedingByteArrayLimit
	}

	b := make([]byte, length)

	if length > 0 {
		_, err := br.Read(b)
		if err != nil {
			return err
		}
	}

	in := dstv.Interface()
	inType := reflect.TypeOf(in)
	dstv.Set(reflect.ValueOf(b).Convert(inType))
	return nil
}

// decodeBytes is used to decode with a destination of []byte
func (br *byteReader) decodeBits(dstv reflect.Value) error {
	length, err := br.decodeLength()
	if err != nil {
		return err
	}
	var v BitSequence
	if err := br.decodeBitsFixedLength(&v, length); err != nil {
		return err
	}
	in := dstv.Interface()
	inType := reflect.TypeOf(in)
	dstv.Set(reflect.ValueOf(v).Convert(inType))
	return nil
}

func (br *byteReader) decodeBitsFixedLength(v *BitSequence, bytesLength uint) (err error) {
	if bytesLength > math.MaxUint32 {
		return ErrExceedingByteArrayLimit
	}
	bb := make([]byte, bytesLength)
	if _, err = br.Reader.Read(bb); err != nil {
		return err
	}
	*v = make(BitSequence, bytesLength*8)
	for i := range *v {
		mod := i % 8
		b := bb[i/8]
		pow2 := byte(1 << mod)   // powers of 2
		(*v)[i] = b&pow2 == pow2 // identify the bit
	}
	return nil
}

// decodeFixedWidth E_{l∈N}(N_{2^8l} → Yl) (eq. C.5)
func (br *byteReader) decodeFixedWidth(dstv reflect.Value, length uint) error {
	typ := dstv.Type()

	// Handle pointers
	if typ.Kind() == reflect.Ptr {
		isNil, err := br.readPointerMarker()
		if err != nil {
			return err
		}
		if isNil {
			dstv.Set(reflect.Zero(typ))

			return nil
		}
		if dstv.IsNil() {
			dstv.Set(reflect.New(typ.Elem()))
		}
		dstv = dstv.Elem()
		typ = typ.Elem()
	}

	// Read the data
	buf := make([]byte, length)
	_, err := br.Read(buf)
	if err != nil {
		return fmt.Errorf(ErrReadingByte, err)
	}

	switch typ.Kind() {
	case reflect.Uint8:
		var temp uint8
		deserializeTrivialNatural(buf, &temp)
		dstv.Set(reflect.ValueOf(temp).Convert(typ))
	case reflect.Uint16:
		var temp uint16
		deserializeTrivialNatural(buf, &temp)
		dstv.Set(reflect.ValueOf(temp).Convert(typ))
	case reflect.Uint32:
		var temp uint32
		deserializeTrivialNatural(buf, &temp)
		dstv.Set(reflect.ValueOf(temp).Convert(typ))
	case reflect.Uint64:
		var temp uint64
		deserializeTrivialNatural(buf, &temp)
		dstv.Set(reflect.ValueOf(temp).Convert(typ))
	case reflect.Int8:
		var temp uint8
		deserializeTrivialNatural(buf, &temp)
		dstv.Set(reflect.ValueOf(int8(temp)).Convert(typ))
	case reflect.Int16:
		var temp uint16
		deserializeTrivialNatural(buf, &temp)
		dstv.Set(reflect.ValueOf(int16(temp)).Convert(typ))
	case reflect.Int32:
		var temp uint32
		deserializeTrivialNatural(buf, &temp)
		dstv.Set(reflect.ValueOf(int32(temp)).Convert(typ))
	case reflect.Int64:
		var temp uint64
		deserializeTrivialNatural(buf, &temp)
		dstv.Set(reflect.ValueOf(int64(temp)).Convert(typ))
	default:
		return fmt.Errorf(ErrUnsupportedType, typ)
	}

	return nil
}

func (br *byteReader) readPointerMarker() (bool, error) {
	var marker [1]byte
	_, err := br.Read(marker[:])
	if err != nil {
		return false, err
	}

	switch marker[0] {
	case 0x00:
		return true, nil // Nil pointer
	case 0x01:
		return false, nil // Non-nil pointer
	default:
		return false, ErrInvalidPointer
	}
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
