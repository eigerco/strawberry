//go:build !tiny

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
	// as specified in the JAM Graypaper. (E)
	TimeslotsPerEpoch = 600

	// EpochDuration defines the total duration of each epoch.
	// It is calculated by multiplying TimeslotsPerEpoch by TimeslotDuration,
	// resulting in a duration of 1 hour per epoch.
	EpochDuration = TimeslotsPerEpoch * TimeslotDuration

	// The number of slots into an epoch at which ticket-submission ends.
	TicketSubmissionTimeSlots = 500

	// R = 10: The rotation period of validator-core assignments, in timeslots.
	ValidatorRotationPeriod = Timeslot(10)

	SlotPeriodInSeconds = 6 // P = 6: The slot period, in seconds

	// The period in timeslots after which an unreferenced preimage may be expunged.
	// D = L + 4,800 where L = 14,400 (maximum age of lookup anchor)
	PreimageExpulsionPeriod = 19_200 // D ≡ L + 4_800 = 19_200 (equation B.3 v0.6.6)
)
