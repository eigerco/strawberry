package jam

import (
	"errors"
)

var (
	// errFirstByteNineByteSerialization is returned when the first byte has wrong value in 9-byte serialization
	errFirstByteNineByteSerialization = errors.New("expected first byte to be 255 for 9-byte serialization")

	ErrEmptyData       = errors.New("empty data")
	ErrNonPointerOrNil = errors.New("value must be a not-nil pointer")

	ErrInvalidBooleanEncoding = errors.New("invalid boolean encoding")

	ErrUnsupportedType     = "unsupported type: %T"
	ErrArrayLengthMismatch = "array length mismatch: expected %d, got %d"
	ErrDataLengthMismatch  = "data length mismatch: expected %d, got %d"
)
