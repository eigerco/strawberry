package validator

import (
	"crypto/ed25519"

	"github.com/eigerco/strawberry/internal/block"
	"github.com/eigerco/strawberry/internal/common"
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/safrole"
)

// ValidatorState represents the state related to validators
type ValidatorState struct {
	CurrentValidators  safrole.ValidatorsData // CurrentValidators mapping (κ) Validator keys and metadata currently active.
	ArchivedValidators safrole.ValidatorsData // Archived validators (λ) Validator keys and metadata which were active in the prior epoch.
	QueuedValidators   safrole.ValidatorsData // Enqueued validators (ι) Validator keys and metadata to be drawn from next.
	SafroleState       safrole.State          // Safrole State (𝛾) (state of block-production algorithm)
}

// ActivityStatisticsState represents the statistics related to validators.
type ActivityStatisticsState struct {
	ValidatorsCurrent [common.NumberOfValidators]ValidatorStatistics // Present validator statistics (π_v) - The activity statistics for the validators which are currently being accumulated.
	ValidatorsLast    [common.NumberOfValidators]ValidatorStatistics // Completed validator statistics (π_l) - The activity statistics for the validators which have completed their work.
	Cores             [common.TotalNumberOfCores]CoreStatistics      // Core statistics (π_c) - The activity statistics for each core.
	Services          []ServiceStatistics                            // Service statistics (π_s) - The activity statistics for each service.
}

type ValidatorStatistics struct {
	NumOfBlocks                 uint32 // Number of blocks (b) - The number of blocks produced by the validator.
	NumOfTickets                uint32 // Number of tickets (t) - The number of tickets introduced by the validator.
	NumOfPreimages              uint32 // Number of preimages (p) - The number of preimages introduced by the validator.
	NumOfBytesAllPreimages      uint32 // Number of bytes across all preimages (d) - The total number of octets across all preimages introduced by the validator.
	NumOfGuaranteedReports      uint32 // Number of guaranteed reports (g) - The number of reports guaranteed by the validator.
	NumOfAvailabilityAssurances uint32 // Number of availability assurances (a) - The number of assurances of availability made by the validator.
}

type CoreStatistics struct {
	// DALoad (d) is the amount of bytes placed into either Audits or Segments DA.
	// This includes the work-bundle (including all extrinsics and imports) as well as all
	// (exported) segments.
	DALoad         uint
	Popularity     uint // Popularity (p) is the number of validators which formed super-majority for assurance.
	Imports        uint // Imports (i) is the number of segments imported from DA made by core for reported work.
	Exports        uint // Exports (e) is the number of segments exported into DA made by core for reported work.
	ExtrinsicSize  uint // ExtrinsicSize (x) is the total size of extrinsics used by core for reported work.
	ExtrinsicCount uint // ExtrinsicCount (z) is the total number of extrinsics used by core for reported work.
	BundleSize     uint // BundleSize (b) is the work-bundle size. This is the size of data being placed into Audits DA by the core.
	// TODO this can break on 32 bit systems, might need a custom type that can general integer encode.
	GasUsed uint // GasUsed (g) is the total gas consumed by core for reported work. Includes all refinement and authorizations.
}

type ServiceActivityRecord struct {
	ProvidedCount   uint // ProvidedCount (p.0) is the number of preimages provided to this service.
	ProvidedSize    uint // ProvidedSize (p.1) is the total size of preimages provided to this service.
	RefinementCount uint // RefinementCount (r.0) is the number of work-items refined by service for reported work.
	// TODO this can break on 32 bit systems, might need a custom type that can general integer encode.
	RefinementGasUsed uint // RefinementGasUsed (r.1) is the amount of gas used for refinement by service for reported work.
	Imports           uint // Imports (i) is the number of segments imported from the DL by service for reported work.
	Exports           uint // Exports (e) is the number of segments exported into the DL by service for reported work.
	ExtrinsicSize     uint // ExtrinsicSize (x) is the total size of extrinsics used by service for reported work.
	ExtrinsicCount    uint // ExtrinsicCount (z) is the total number of extrinsics used by service for reported work.
	AccumulateCount   uint // AccumulateCount (a.0) is the number of work-items accumulated by service.
	// TODO this can break on 32 bit systems, might need a custom type that can general integer encode.
	AccumulateGasUsed uint // AccumulateGasUsed (a.1) is the amount of gas used for accumulation by service.
	OnTransfersCount  uint // OnTransfersCount (t.0) is the number of transfers processed by service.
	// TODO this can break on 32 bit systems, might need a custom type that can general integer encode.
	OnTransfersGasUsed uint // OnTransfersGasUsed (t.1) is the amount of gas used for processing transfers by service.
}

type ServiceStatistics struct {
	ID     block.ServiceId       // ID is the service identifier
	Record ServiceActivityRecord // Record contains the activity metrics for the service
}

// Implements equation 59 from the graypaper, i.e Φ(k). If any of the queued
// validator data matches the offenders list (ψ′), all the keys for that
// validator are zero'd out.
func NullifyOffenders(queuedValidators safrole.ValidatorsData, offenders []ed25519.PublicKey) safrole.ValidatorsData {
	offenderMap := make(crypto.ED25519PublicKeySet)
	for _, key := range offenders {
		offenderMap.Add(key)
	}
	for i, validator := range queuedValidators {
		if offenderMap.Has(validator.Ed25519) {
			queuedValidators[i] = crypto.ValidatorKey{
				// Ensure these 32 bytes are zero'd out, and not just nil.  TODO
				// - maybe use a custom wrapper type for [32]byte ?
				Ed25519: make([]byte, 32),
			} // Nullify the validator.
		}
	}
	return queuedValidators
}
