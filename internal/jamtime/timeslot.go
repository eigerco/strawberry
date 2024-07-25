package jamtime

import "time"

const (
	TimeslotDuration = 6 * time.Second
)

// Timeslot represents a 6-second window in JAM time
type Timeslot uint32

// FromTimeslot creates a JamTime from a Timeslot (start of the timeslot)
func FromTimeslot(ts Timeslot) JamTime {
	return JamTime{Seconds: uint64(ts) * uint64(TimeslotDuration.Seconds())}
}

// CurrentTimeslot returns the current timeslot
func CurrentTimeslot() Timeslot {
	return Now().ToTimeslot()
}

// IsInFutureTimeslot checks if a given Timeslot is in the future
func (ts Timeslot) IsInFuture() bool {
	return ts > CurrentTimeslot()
}

// TimeslotStart returns the JamTime at the start of the timeslot
func (ts Timeslot) TimeslotStart() JamTime {
	return FromTimeslot(ts)
}

// TimeslotEnd returns the JamTime at the end of the timeslot
func (ts Timeslot) TimeslotEnd() JamTime {
	return FromTimeslot(ts + 1).Add(-time.Nanosecond)
}

// NextTimeslot returns the next timeslot
func (ts Timeslot) NextTimeslot() Timeslot {
	return ts + 1
}

// PreviousTimeslot returns the previous timeslot
func (ts Timeslot) PreviousTimeslot() Timeslot {
	return ts - 1
}

// TimeslotInEpoch returns the timeslot number within the epoch (0-599)
func (ts Timeslot) TimeslotInEpoch() uint32 {
	return uint32(ts % TimeslotsPerEpoch)
}

// IsFirstTimeslotInEpoch checks if the timeslot is the first in its epoch
func (ts Timeslot) IsFirstTimeslotInEpoch() bool {
	return ts.TimeslotInEpoch() == 0
}

// IsLastTimeslotInEpoch checks if the timeslot is the last in its epoch
func (ts Timeslot) IsLastTimeslotInEpoch() bool {
	return ts.TimeslotInEpoch() == TimeslotsPerEpoch-1
}

// ValidateTimeslot checks if a given Timeslot is within the valid range
func ValidateTimeslot(ts Timeslot) error {
	jamTime := FromTimeslot(ts)
	return ValidateJamTime(jamTime.ToTime())
}
