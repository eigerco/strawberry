package time

import "time"

const (
	TimeslotsPerEpoch = 600
	TimeslotDuration  = 6 * time.Second
	EpochDuration     = TimeslotsPerEpoch * TimeslotDuration
)
