package jamtime

import (
	"fmt"
	"time"
)

var now = time.Now

// JamEpoch represents the start of the JAM Common Era
// 2024-01-01 12:00:00
var JamEpoch = time.Date(2024, time.January, 1, 12, 0, 0, 0, time.UTC)

// MaxRepresentableJamTime is the latest date and time that can be represented
// in the JAM protocol. It corresponds to the end of the last timeslot in the
// last epoch (2^32 - 1 timeslots after the JAM Epoch). This time is set to
// 23:59:59.999999999 UTC on August 15, 2840, as specified in the JAM Graypaper.
// Any attempt to represent a time beyond this will result in an error.
var MaxRepresentableJamTime = time.Date(2840, time.August, 15, 23, 59, 59, 999999999, time.UTC)

// JamTime represents a time in the JAM Common Era
type JamTime struct {
	src     time.Time
	Seconds uint64
}

// Now returns the current time as a JamTime
func Now() JamTime {
	t := now()
	seconds := t.Unix() - JamEpoch.Unix()

	return JamTime{src: t, Seconds: uint64(seconds)}
}

// FromTime converts a standard time.Time to JamTime
func FromTime(t time.Time) (JamTime, error) {
	if t.Before(JamEpoch) {
		return JamTime{}, ErrBeforeJamEpoch
	}

	if t.Equal(JamEpoch) {
		return JamTime{Seconds: 0}, nil
	}

	if t.After(MaxRepresentableJamTime) {
		return JamTime{}, ErrAfterMaxJamTime
	}

	seconds := t.Unix() - JamEpoch.Unix()

	return JamTime{src: t, Seconds: uint64(seconds)}, nil
}

// EpochAndTimeslotToJamTime converts an Epoch and a timeslot within that epoch to JamTime
func EpochAndTimeslotToJamTime(e Epoch, timeslot Timeslot) (JamTime, error) {
	if timeslot >= TimeslotsPerEpoch {
		return JamTime{}, ErrTimeslotExceedsEpochLength
	}
	epochStart := FromEpoch(e)
	return JamTime{Seconds: epochStart.Seconds + uint64(timeslot)*uint64(TimeslotDuration.Seconds())}, nil
}

// ToTime converts a JamTime to a standard time.Time
func (jt JamTime) ToTime() time.Time {
	if jt.src.IsZero() {
		t := JamEpoch.Unix() + int64(jt.Seconds)

		return time.Unix(t, 0).UTC()
	}

	return jt.src
}

// FromSeconds creates a JamTime from the number of seconds since the JAM Epoch
func FromSeconds(seconds uint64) JamTime {
	return JamTime{Seconds: seconds}
}

// Before reports whether the time instant jt is before u
func (jt JamTime) Before(u JamTime) bool {
	return jt.Seconds < u.Seconds
}

// After reports whether the time instant jt is after u
func (jt JamTime) After(u JamTime) bool {
	return jt.Seconds > u.Seconds
}

// Equal reports whether jt and u represent the same time instant
func (jt JamTime) Equal(u JamTime) bool {
	return jt.Seconds == u.Seconds
}

// Add returns the time jt+d
func (jt JamTime) Add(d time.Duration) (JamTime, error) {
	// Get JamTime back in time.Time representation
	t := jt.ToTime()
	t = t.Add(d)

	// Check for overflow after MaxRepresentableJamTime
	if t.After(MaxRepresentableJamTime) {
		return JamTime{}, ErrAfterMaxJamTime
	}

	// Check for underflow past JamEpoch
	if t.Before(JamEpoch) {
		return JamTime{}, ErrBeforeJamEpoch
	}

	return FromTime(t)
}

// Sub returns the duration jt-u
func (jt JamTime) Sub(u JamTime) time.Duration {
	return time.Duration(int64(jt.Seconds-u.Seconds)) * time.Second
}

// IsInFutureTimeSlot checks if a given JamTime is in a future timeslot
func (jt JamTime) IsInFutureTimeSlot() bool {
	return jt.ToTimeslot() > CurrentTimeslot()
}

// ToTimeslot converts a JamTime to its corresponding Timeslot
func (jt JamTime) ToTimeslot() Timeslot {
	return Timeslot(jt.Seconds / uint64(TimeslotDuration.Seconds()))
}

// IsZero reports whether jt represents the zero time instant,
// IsZero is true when the date and time equal to 2024-01-01 12:00:00
func (jt JamTime) IsZero() bool {
	return jt.Seconds == 0
}

// MarshalJSON implements the json.Marshaler interface
func (jt JamTime) MarshalJSON() ([]byte, error) {
	return []byte(fmt.Sprintf(`"%s"`, []byte(jt.ToTime().Format(time.RFC3339)))), nil
}

// UnmarshalJSON implements the json.Unmarshaler interface
func (jt *JamTime) UnmarshalJSON(data []byte) error {
	t, err := time.Parse(`"`+time.RFC3339+`"`, string(data))
	if err != nil {
		return err
	}
	*jt, err = FromTime(t)
	if err != nil {
		return err
	}
	return nil
}

// ToEpochAndTimeslot converts a JamTime to its Epoch and timeslot within that epoch
func (jt JamTime) ToEpochAndTimeslot() (Epoch, Timeslot) {
	epoch := jt.ToEpoch()
	timeslotInEpoch := uint32((jt.Seconds / uint64(TimeslotDuration.Seconds())) % TimeslotsPerEpoch)
	return epoch, Timeslot(timeslotInEpoch)
}

// IsInSameEpoch checks if two JamTimes are in the same epoch
func (jt JamTime) IsInSameEpoch(other JamTime) bool {
	return jt.ToEpoch() == other.ToEpoch()
}

// ToEpoch converts a JamTime to its corresponding Epoch
func (jt JamTime) ToEpoch() Epoch {
	return Epoch(jt.Seconds / uint64(EpochDuration.Seconds()))
}

// ValidateJamTime checks if a given time.Time is within the valid range for JamTime
// Returns nil if valid and non-nil err if the given time.Time is outside the valid range for JamTime
func ValidateJamTime(t time.Time) error {
	if t.Before(JamEpoch) {
		return ErrBeforeJamEpoch
	}
	if t.After(MaxRepresentableJamTime) {
		return ErrAfterMaxJamTime
	}
	return nil
}
