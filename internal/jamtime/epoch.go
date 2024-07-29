package jamtime

import (
	"errors"
	"time"
)

const (
	TimeslotsPerEpoch = 600
	EpochDuration     = TimeslotsPerEpoch * TimeslotDuration // 1 hour
)

// Epoch represents a JAM Epoch
type Epoch uint32

// FromEpoch creates a JamTime from an Epoch (start of the epoch)
func FromEpoch(e Epoch) JamTime {
	return JamTime{Seconds: uint64(e) * uint64(EpochDuration.Seconds())}
}

// CurrentEpoch returns the current epoch
func CurrentEpoch() Epoch {
	return Now().ToEpoch()
}

// EpochStart returns the JamTime at the start of the epoch
func (e Epoch) EpochStart() JamTime {
	return FromEpoch(e)
}

// EpochEnd returns the JamTime at the end of the epoch
func (e Epoch) EpochEnd() JamTime {
	return FromEpoch(e + 1).Add(-time.Nanosecond)
}

// NextEpoch returns the next epoch
func (e Epoch) NextEpoch() Epoch {
	maxEpoch := Epoch((1<<32 - 1) / TimeslotsPerEpoch)
	if e == maxEpoch {
		return 0
	}
	return e + 1
}

// PreviousEpoch returns the previous epoch
func (e Epoch) PreviousEpoch() Epoch {
	return e - 1 // This will naturally wrap around at 0
}

// ValidateEpoch checks if a given Epoch is within the valid range
func ValidateEpoch(e Epoch) error {
	maxEpoch := Epoch((1<<32 - 1) / TimeslotsPerEpoch)
	if e > maxEpoch {
		return errors.New("epoch is after maximum representable JAM time")
	}
	return nil
}
