//go:build !tiny && !conformance

package constants

// Chain specific constants by configuration, eg tiny

const (
	// (V) The total number of validators
	NumberOfValidators = 1023

	// TimeslotsPerEpoch defines the number of timeslots in each epoch.
	// In the JAM protocol, each epoch consists of exactly 600 timeslots,
	// as specified in the JAM Graypaper. (E)
	TimeslotsPerEpoch = 600

	// (C) Total number of cores in the system
	TotalNumberOfCores uint16 = 341

	// MaxTimeslotsForLookupAnchor (L) Maximum age for lookup-anchor blocks in work reports
	MaxTimeslotsForLookupAnchor = 14400

	// R = 10: The rotation period of validator-core assignments, in timeslots.
	ValidatorRotationPeriod = 10

	// The period in timeslots after which an unreferenced preimage may be expunged.
	// D = L + 4,800 where L = 14,400 (maximum age of lookup anchor)
	PreimageExpulsionPeriod = 19_200 // D = L + 4_800 = 19_200 (equation B.3 v0.6.6)

	// The number of slots into an epoch at which ticket-submission ends.
	TicketSubmissionTimeSlots = 500

	// The maximum number of tickets which may be submitted in a single extrinsic.
	MaxTicketExtrinsicSize = 16

	// N = 2: The number of ticket entries per validator.
	MaxTicketAttemptsPerValidator = 2

	// K: The maximum number of tickets which may be submitted in a single extrinsic.
	MaxTicketsPerBlock = 16

	// WP = 6: The number of erasure-coded pieces in a segment.
	NumberOfErasureCodecPiecesInSegment = 6

	// The number of original shards.
	ErasureCodingOriginalShards = 342

	// WE = 684: The basic size of erasure-coded pieces in octets.
	ErasureCodingChunkSize = 684

	// GR = 5,000,000,000: The gas allocated to invoke a work-package's Refine logic.
	MaxAllocatedGasRefine = 5_000_000_000

	// GT = 3,500,000,000: Total gas allocated across all cores for Accumulation
	TotalGasAccumulation = 3_500_000_000
)
