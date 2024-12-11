//go:build integration

package common

import "github.com/eigerco/strawberry/internal/jamtime"

const (
	NumberOfValidators                           = 6
	AvailabilityThreshold                        = (2 * NumberOfValidators) / 3 // Calculate the availability threshold (2/3 V)
	TotalNumberOfCores                    uint16 = 2
	ValidatorsSuperMajority                      = (2 * NumberOfValidators / 3) + 1
	WorkReportTimeoutPeriod                      = jamtime.Timeslot(5)
	ValidatorRotationPeriod                      = jamtime.Timeslot(10)
	MaxTicketExtrinsicSize                       = 16
	MaxHistoricalTimeslotsForPreimageMeta        = 3
	MaxAllocatedGasAccumulation                  = 100_000
	SizeOfSegment                                = 4104
)
