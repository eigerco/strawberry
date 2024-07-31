package jamtime

import "errors"

var (
	// ErrMinEpochReached is returned when attempting to get the previous epoch
	// from the minimum possible epoch value.
	ErrMinEpochReached = errors.New("minimum epoch reached")

	// ErrMaxEpochReached is returned when attempting to get the next epoch
	// from the maximum possible epoch value.
	ErrMaxEpochReached = errors.New("maximum epoch reached")

	// ErrEpochExceedsMaxJamTime is returned when an epoch value exceeds the maximum
	// representable time in the JAM system, typically during epoch calculations
	// or conversions.
	ErrEpochExceedsMaxJamTime = errors.New("epoch is after maximum representable JAM time")

	// ErrMinTimeslotReached is returned when attempting to get the previous timeslot
	// from the minimum possible timeslot value.
	ErrMinTimeslotReached = errors.New("minimum timeslot reached")

	// ErrMaxTimeslotReached is returned when attempting to get the next timeslot
	// from the maximum possible timeslot value.
	ErrMaxTimeslotReached = errors.New("maximum timeslot reached")

	// ErrTimeslotExceedsEpochLength is returned when a timeslot number is greater than
	// or equal to the number of timeslots in an epoch. This typically occurs when
	// converting between epochs and timeslots or when validating timeslot values.
	ErrTimeslotExceedsEpochLength = errors.New("timeslot number exceeds epoch length")
)
