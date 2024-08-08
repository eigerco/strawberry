package jamtime

import (
	"time"
)

const (
	// MinEpoch represents the first epoch in the JAM protocol.
	// It corresponds to the epoch containing the JAM Epoch start time
	// (12:00pm on January 1, 2024 UTC).
	MinEpoch Epoch = 0

	// MaxEpoch represents the last possible epoch in the JAM protocol.
	// It is calculated as the maximum value of Epoch (uint32) divided by
	// TimeslotsPerEpoch. This ensures that the last epoch can contain
	// a full complement of timeslots without overflowing.
	MaxEpoch Epoch = ^Epoch(0) / TimeslotsPerEpoch

	// TimeslotsPerEpoch defines the number of timeslots in each epoch.
	// In the JAM protocol, each epoch consists of exactly 600 timeslots,
	// as specified in the JAM Graypaper.
	TimeslotsPerEpoch = 600

	// EpochDuration defines the total duration of each epoch.
	// It is calculated by multiplying TimeslotsPerEpoch by TimeslotDuration,
	// resulting in a duration of 1 hour per epoch.
	EpochDuration = TimeslotsPerEpoch * TimeslotDuration
)

// Epoch represents a JAM Epoch
type Epoch uint32

// FromEpoch creates a JamTime from an Epoch (start of the epoch)
func FromEpoch(e Epoch) JamTime {
	return JamTime{Seconds: uint64(e) * uint64(EpochDuration.Seconds())}
}

// CurrentEpoch returns the current epoch
func CurrentEpoch() Epoch {
	now, _ := Now()
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
