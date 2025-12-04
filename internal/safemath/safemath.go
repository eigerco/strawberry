package safemath

import (
	"errors"
	"math/bits"
)

var ErrOverflow = errors.New("number overflow")

func Add32(a, b uint32) (uint32, bool) {
	v, carry := bits.Add32(a, b, 0)
	return v, carry == 0
}

func Add64(a, b uint64) (uint64, bool) {
	v, carry := bits.Add64(a, b, 0)
	return v, carry == 0
}

func Sub32(a, b uint32) (uint32, bool) {
	v, carry := bits.Sub32(a, b, 0)
	return v, carry == 0
}

func Sub64(a, b uint64) (uint64, bool) {
	v, carry := bits.Sub64(a, b, 0)
	return v, carry == 0
}
