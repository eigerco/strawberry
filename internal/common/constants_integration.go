//go:build tiny

package common

import "github.com/eigerco/strawberry/internal/jamtime"

const (
	NumberOfValidators                           = 6
	AvailabilityThreshold                        = (2 * NumberOfValidators) / 3 // Calculate the availability threshold (2/3 V)
	TotalNumberOfCores                    uint16 = 2
	ValidatorsSuperMajority               uint16 = (2 * NumberOfValidators / 3) + 1
	WorkReportTimeoutPeriod                      = jamtime.Timeslot(5)
	MaxTicketExtrinsicSize                       = 3
	MaxTicketAttemptsPerValidator                = 3
	MaxHistoricalTimeslotsForPreimageMeta        = 3
	SizeOfSegment                                = NumberOfErasureCodecPiecesInSegment * ErasureCodingChunkSize
	MaxWorkPackageSize                           = 13_791_360
	NumberOfErasureCodecPiecesInSegment          = 1026
	ErasureCodingOriginalShards                  = 2
	ErasureCodingChunkSize                       = 4
	MaxAllocatedGasRefine                        = 1_000_000_000
	MaxAllocatedGasAccumulation                  = 10_000_000
	MaxAllocatedGasIsAuthorized                  = 50_000_000
	TotalGasAccumulation                         = 20_000_000

	WorkReportMaxSumOfDependencies = 8
	MaxWorkPackageSizeBytes        = 48 * 1024
	MaxNrImportsExports            = 3072
)
