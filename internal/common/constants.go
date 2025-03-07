//go:build !integration

package common

import "github.com/eigerco/strawberry/internal/jamtime"

const (
	NumberOfValidators                           = 1023                                                         // (V) The total number of validators
	AvailabilityThreshold                        = (2 * NumberOfValidators) / 3                                 // Calculate the availability threshold (2/3 V)
	TotalNumberOfCores                    uint16 = 341                                                          // (C) Total number of cores in the system
	ValidatorsSuperMajority                      = (2 * NumberOfValidators / 3) + 1                             // 2/3V + 1
	WorkReportTimeoutPeriod                      = jamtime.Timeslot(5)                                          // U = 5: The period in timeslots after which reported but unavailable work may be replaced.
	ValidatorRotationPeriod                      = jamtime.Timeslot(10)                                         // R = 10: The rotation period of validator-core assignments, in timeslots.
	MaxTicketExtrinsicSize                       = 16                                                           // The maximum number of tickets which may be submitted in a single extrinsic.
	MaxTicketAttempts                            = 2                                                            // N = 2: The number of ticket entries per validator.
	MaxHistoricalTimeslotsForPreimageMeta        = 3                                                            // () Maximum number of historical timeslots for preimage metadata
	SizeOfSegment                                = NumberOfErasureCodecPiecesInSegment * ErasureCodingChunkSize // WG = WP*WE = 4104: The size of a segment in octets.
	MaxWorkPackageSize                           = 12 * 1 << 20                                                 // WB = 12 MB: The maximum size of an encoded work-package in octets (including extrinsic data and import implications).
	NumberOfErasureCodecPiecesInSegment          = 6                                                            // WP = 6: The number of erasure-coded pieces in a segment.
	ErasureCodingChunkSize                       = 684                                                          // WE = 684: The basic size of erasure-coded pieces in octets.
	MaxAllocatedGasAccumulation                  = 10_000_000                                                   // GA: The gas allocated to invoke a work-report’s Accumulation logic.
	MaxAllocatedGasIsAuthorized                  = 50_000_000                                                   // GI: The gas allocated to invoke a work-package’s Is-Authorized logic.
	WorkReportMaxSumOfDependencies               = 8                                                            // (J) The maximum sum of dependency items in a work-report.
	MaxWorkPackageSizeBytes                      = 48 * 1024                                                    // (WR) Maximum size of a serialized work-package in bytes
)
