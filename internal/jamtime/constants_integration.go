//go:build integration

package jamtime

const (
	MinEpoch                  Epoch = 0
	MaxEpoch                  Epoch = ^Epoch(0) / TimeslotsPerEpoch
	TimeslotsPerEpoch               = 12
	EpochDuration                   = TimeslotsPerEpoch * TimeslotDuration
	TicketSubmissionTimeSlots       = 10
)
