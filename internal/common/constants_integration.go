//go:build integration

package common

import "github.com/eigerco/strawberry/internal/jamtime"

const (
	NumberOfValidators             = 6
	TotalNumberOfCores      uint16 = 2
	ValidatorsSuperMajority        = (2 * NumberOfValidators / 3) + 1
	WorkReportTimeoutPeriod        = jamtime.Timeslot(5)
	ValidatorRotationPeriod        = jamtime.Timeslot(10)
	MaxTicketExtrinsicSize         = 16
)
