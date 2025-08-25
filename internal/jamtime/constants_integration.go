//go:build integration

package jamtime

const (
	MinEpoch                  Epoch = 0
	MaxEpoch                  Epoch = ^Epoch(0) / TimeslotsPerEpoch
	TimeslotsPerEpoch               = 12
	EpochDuration                   = TimeslotsPerEpoch * TimeslotDuration
	TicketSubmissionTimeSlots       = 10
	ValidatorRotationPeriod         = Timeslot(4)
	SlotPeriodInSeconds             = 6
	PreimageExpulsionPeriod         = 32 // see https://github.com/davxy/jam-test-vectors/tree/master/traces#preimage-expunge-delay
)
