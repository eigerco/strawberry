//go:build integration

package common

import "github.com/eigerco/strawberry/internal/jamtime"

const (
	NumberOfValidators                           = 6
	AvailabilityThreshold                        = (2 * NumberOfValidators) / 3 // Calculate the availability threshold (2/3 V)
	TotalNumberOfCores                    uint16 = 2
	ValidatorsSuperMajority                      = (2 * NumberOfValidators / 3) + 1
	WorkReportTimeoutPeriod                      = jamtime.Timeslot(5)
	ValidatorRotationPeriod                      = jamtime.Timeslot(4)
	MaxTicketExtrinsicSize                       = 16
	MaxTicketAttempts                            = 3
	MaxHistoricalTimeslotsForPreimageMeta        = 3
	SizeOfSegment                                = NumberOfErasureCodecPiecesInSegment * ErasureCodingChunkSize
	MaxWorkPackageSize                           = 12 * 1 << 20
	NumberOfErasureCodecPiecesInSegment          = 6
	ErasureCodingChunkSize                       = 684
	MaxAllocatedGasAccumulation                  = 10_000_000
	MaxAllocatedGasIsAuthorized                  = 50_000_000
	WorkReportMaxSumOfDependencies               = 8
	MaxWorkPackageSizeBytes                      = 48 * 1024
)
