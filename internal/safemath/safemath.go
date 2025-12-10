package safemath

import "errors"

type Integer interface {
	~int | ~int8 | ~int16 | ~int32 | ~int64 |
		~uint | ~uint8 | ~uint16 | ~uint32 | ~uint64 | ~uintptr
}

var ErrOverflow = errors.New("number overflow")

// Add handles safe addition for both Signed and Unsigned integers.
// Returns the result and true if successful, or zero and false on overflow.
func Add[T Integer](a, b T) (T, bool) {
	sum := a + b

	// Check if T is Signed by checking if bitwise-not-zero is negative.
	// (^T(0) == -1 for signed, MaxUint for unsigned)
	if (^T(0)) < 0 {
		// --- Signed Logic ---
		// Overflow if a and b have same sign, but sum has different sign.
		if (a^sum) < 0 && (b^sum) < 0 {
			return 0, false
		}
	} else {
		// --- Unsigned Logic ---
		// Overflow if sum wraps around and becomes smaller than operand.
		if sum < a {
			return 0, false
		}
	}

	return sum, true
}

// Sub handles safe subtraction for both Signed and Unsigned integers.
// Returns the result and true if successful, or zero and false on overflow.
func Sub[T Integer](a, b T) (T, bool) {
	diff := a - b

	if (^T(0)) < 0 {
		// --- Signed Logic ---
		// Overflow if operands have different signs,
		// and result has different sign than a.
		if (a^b) < 0 && (a^diff) < 0 {
			return 0, false
		}
	} else {
		// --- Unsigned Logic ---
		// Overflow if we subtract a larger number from a smaller one.
		if a < b {
			return 0, false
		}
	}

	return diff, true
}

// Mul handles safe multiplication for both Signed and Unsigned integers.
// Returns the result and true if successful, or zero and false on overflow.
func Mul[T Integer](a, b T) (T, bool) {
	if a == 0 || b == 0 {
		return 0, true
	}

	result := a * b

	if (^T(0)) < 0 {
		// --- Signed Logic ---
		if result/b != a {
			return 0, false
		}

		// Special Case: MinInt * -1
		// We avoid using literal -1 because it breaks uint compilation.
		// ^T(0) is -1 for signed types.
		minusOne := ^T(0)

		// In 2's complement, MinInt is the only value where x == -x (except 0).
		if (a == minusOne && b == -b) || (b == minusOne && a == -a) {
			return 0, false
		}
	} else {
		// --- Unsigned Logic ---
		if result/b != a {
			return 0, false
		}
	}

	return result, true
}
