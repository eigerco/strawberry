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

// ToEpoch converts a JamTime to its corresponding Epoch
func (jt JamTime) ToEpoch() Epoch {
	return Epoch(jt.Seconds / uint64(EpochDuration.Seconds()))
}

// FromEpoch creates a JamTime from an Epoch (start of the epoch)
func FromEpoch(e Epoch) JamTime {
	return JamTime{Seconds: uint64(e) * uint64(EpochDuration.Seconds())}
}

// ToEpoch converts a Timeslot to its corresponding Epoch
func (ts Timeslot) ToEpoch() Epoch {
	return Epoch(ts / TimeslotsPerEpoch)
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
	return e + 1
}

// PreviousEpoch returns the previous epoch
func (e Epoch) PreviousEpoch() Epoch {
	return e - 1
}

// ValidateEpoch checks if a given Epoch is within the valid range
func ValidateEpoch(e Epoch) error {
	jamTime := FromEpoch(e)
	return ValidateJamTime(jamTime.ToTime())
}

// EpochAndTimeslotToJamTime converts an Epoch and a timeslot within that epoch to JamTime
func EpochAndTimeslotToJamTime(e Epoch, timeslotInEpoch uint32) (JamTime, error) {
	if timeslotInEpoch >= TimeslotsPerEpoch {
		return JamTime{}, errors.New("timeslot number exceeds epoch length")
	}
	epochStart := FromEpoch(e)
	return JamTime{Seconds: epochStart.Seconds + uint64(timeslotInEpoch)*uint64(TimeslotDuration.Seconds())}, nil
}
