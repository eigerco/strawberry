//go:build !integration

package common

import "github.com/eigerco/strawberry/internal/jamtime"

const (
	NumberOfValidators                           = 1023                             // (V) The total number of validators
	TotalNumberOfCores                    uint16 = 341                              // (C) Total number of cores in the system
	ValidatorsSuperMajority                      = (2 * NumberOfValidators / 3) + 1 // 2/3V + 1
	WorkReportTimeoutPeriod                      = jamtime.Timeslot(5)              // U = 5: The period in timeslots after which reported but unavailable work may be replaced.
	ValidatorRotationPeriod                      = jamtime.Timeslot(10)             // R = 10: The rotation period of validator-core assignments, in timeslots.
	MaxTicketExtrinsicSize                       = 16                               // The maximum number of tickets which may be submitted in a single extrinsic.
	MaxHistoricalTimeslotsForPreimageMeta        = 3                                // () Maximum number of historical timeslots for preimage metadata
	SizeOfExportedSegment                        = 6                                // (WS) The size of an exported segment in erasure-coded pieces in octets.
)
