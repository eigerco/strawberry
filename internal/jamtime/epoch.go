package jamtime

import (
	"time"
)

// Epoch represents a JAM Epoch
type Epoch uint32

// FromEpoch creates a JamTime from an Epoch (start of the epoch)
func FromEpoch(e Epoch) JamTime {
	return JamTime{Seconds: uint64(e) * uint64(EpochDuration.Seconds())}
}

// CurrentEpoch returns the current epoch
func CurrentEpoch() Epoch {
	now := Now()
	return now.ToEpoch()
}

// EpochStart returns the JamTime at the start of the epoch
func (e Epoch) EpochStart() JamTime {
	return FromEpoch(e)
}

// EpochEnd returns the JamTime at the end of the epoch
func (e Epoch) EpochEnd() (JamTime, error) {
	if e == MaxEpoch {
		// For the last epoch, we calculate its end based on the last timeslot
		return FromTimeslot(MaxTimeslot), nil
	}

	return FromEpoch(e + 1).Add(-time.Nanosecond)
}

// NextEpoch returns the next epoch
func (e Epoch) NextEpoch() (Epoch, error) {
	if e == MaxEpoch {
		return e, ErrMaxEpochReached
	}
	return e + 1, nil
}

// PreviousEpoch returns the previous epoch
func (e Epoch) PreviousEpoch() (Epoch, error) {
	if e == MinEpoch {
		return e, ErrMinEpochReached
	}
	return e - 1, nil
}

// ValidateEpoch checks if a given Epoch is within the valid range
func ValidateEpoch(e Epoch) error {
	if e > MaxEpoch {
		return ErrEpochExceedsMaxJamTime
	}
	return nil
}
