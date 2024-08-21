package jam

import (
	"errors"
)

var (
	errNotEnoughBytesToDeserializeNumber = errors.New("not enough bytes to deserialize the number")

	ErrEmptyData       = errors.New("empty data")
	ErrNonPointerOrNil = errors.New("value must be a not-nil pointer")

	ErrInvalidBooleanEncoding = errors.New("invalid boolean encoding")

	ErrUnsupportedType     = "unsupported type: %T"
	ErrArrayLengthMismatch = "array length mismatch: expected %d, got %d"
	ErrDataLengthMismatch  = "data length mismatch: expected %d, got %d"
)
