package jam

import (
	"errors"
)

var (
	// errFirstByteNineByteSerialization is returned when the first byte has wrong value in 9-byte serialization
	errFirstByteNineByteSerialization = errors.New("expected first byte to be 255 for 9-byte serialization")
	ErrInvalidPointer                 = errors.New("invalid pointer")
	ErrDecodingBool                   = errors.New("error decoding boolean")
	ErrExceedingByteArrayLimit        = errors.New("byte array length exceeds max value of uint32")

	ErrUnsupportedType         = "unsupported type: %v"
	ErrReadingBytes            = "error reading bytes: %w"
	ErrReadingByte             = "error reading byte: %w"
	ErrDecodingUint            = "error decoding uint: : %w"
	ErrEncodingMapFieldKeyType = "error encoding map field: unsupported map key type %v"
	ErrDecodingMapLength       = "error decoding map length: %v"
	ErrDecodingMapKey          = "error decoding map key: %v"
	ErrDecodingMapValue        = "error decoding map value: %v"
	ErrEncodingStructField     = "encoding struct field '%s': %w"
	ErrDecodingStructField     = "decoding struct field '%s': %w"
)
