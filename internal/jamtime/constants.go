//go:build !integration

package jamtime

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
