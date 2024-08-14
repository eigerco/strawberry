package jam

import "errors"

var (
	// errFirstByteNineByteSerialization is returned when the first byte has wrong value in 9-byte serialization
	errFirstByteNineByteSerialization = errors.New("expected first byte to be 255 for 9-byte serialization")

	// ErrDataTooLongForUintType indicates data exceeds the uint type's size.
	ErrDataTooLongForUintType = errors.New("serialized data is too long for the target uint type")
)
