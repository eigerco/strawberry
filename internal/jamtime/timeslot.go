package jamtime

import (
	"time"
)

const (
	// MinTimeslot represents the first timeslot in the JAM protocol.
	// It corresponds to the beginning of the JAM Epoch (12:00pm on January 1, 2024 UTC).
	MinTimeslot Timeslot = 0

	// MaxTimeslot represents the last possible timeslot in the JAM protocol.
	// It is set to the maximum value of a uint32 (2^32 - 1), which allows
	// the protocol to represent time up to mid-August 2840.
	MaxTimeslot Timeslot = ^Timeslot(0)

	// TimeslotDuration defines the length of each timeslot in the JAM protocol.
	// Each timeslot is exactly 6 seconds long, as specified in the JAM Graypaper.
	// This constant duration is used for conversions between timeslots and actual time.
	TimeslotDuration = 6 * time.Second

	// PreimageExpulsionPeriod (D) = 28,800:
	// The period in timeslots after which an unreferenced preimage may be expunged.
	PreimageExpulsionPeriod = 28_800
)

// Timeslot represents a 6-second window in JAM time
type Timeslot uint32

// FromTimeslot creates a JamTime from a Timeslot (start of the timeslot)
func FromTimeslot(ts Timeslot) JamTime {
	return JamTime{Seconds: uint64(ts) * uint64(TimeslotDuration.Seconds())}
}

// CurrentTimeslot returns the current timeslot
func CurrentTimeslot() Timeslot {
	now := Now()
	return now.ToTimeslot()
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
func (ts Timeslot) TimeslotEnd() (JamTime, error) {
	if ts == MaxTimeslot {
		return JamTime{}, ErrMaxTimeslotReached
	}

	nextTs := ts + 1
	jamTime := FromTimeslot(nextTs)
	return jamTime.Add(-time.Nanosecond)
}

// NextTimeslot returns the next timeslot
func (ts Timeslot) NextTimeslot() (Timeslot, error) {
	if ts == MaxTimeslot {
		return ts, ErrMaxTimeslotReached
	}
	return ts + 1, nil
}

// PreviousTimeslot returns the previous timeslot
func (ts Timeslot) PreviousTimeslot() (Timeslot, error) {
	if ts == MinTimeslot {
		return ts, ErrMinTimeslotReached
	}
	return ts - 1, nil
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

// ToEpoch converts a Timeslot to its corresponding Epoch
func (ts Timeslot) ToEpoch() Epoch {
	return Epoch(ts / TimeslotsPerEpoch)
}

// ValidateTimeslot checks if a given Timeslot is within the valid range
func ValidateTimeslot(ts Timeslot) error {
	jamTime := FromTimeslot(ts)
	return ValidateJamTime(jamTime.ToTime())
}

// IsTicketSubmissionPeriod checks if tickets can still be submitted in the given Timeslot
func (ts Timeslot) IsTicketSubmissionPeriod() bool {
	return ts.TimeslotInEpoch() < TicketSubmissionTimeSlots
}

// IsWinningTicketMarkerPeriod checks if it's the first available Timeslot after
// the ticket submission lottery ends and where the winning ticket marker can be
// generated.
func (ts Timeslot) IsWinningTicketMarkerPeriod(previous Timeslot) bool {
	return previous.TimeslotInEpoch() < TicketSubmissionTimeSlots &&
		TicketSubmissionTimeSlots <= ts.TimeslotInEpoch()
}
