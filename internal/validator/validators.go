package validator

import (
	"io"

	"github.com/eigerco/strawberry/internal/crypto/ed25519"

	"github.com/eigerco/strawberry/internal/block"
	"github.com/eigerco/strawberry/internal/constants"
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/safrole"
	"github.com/eigerco/strawberry/pkg/serialization/codec/jam"
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
	ValidatorsCurrent [constants.NumberOfValidators]ValidatorStatistics // Present validator statistics (π_v) - The activity statistics for the validators which are currently being accumulated.
	ValidatorsLast    [constants.NumberOfValidators]ValidatorStatistics // Completed validator statistics (π_l) - The activity statistics for the validators which have completed their work.
	Cores             [constants.TotalNumberOfCores]CoreStatistics      // Core statistics (π_c) - The activity statistics for each core.
	Services          ServiceStatistics                                 // Service statistics (π_s) - The activity statistics for each service.
}

type ValidatorStatistics struct {
	NumOfBlocks                 uint32 // Number of blocks (b) - The number of blocks produced by the validator.
	NumOfTickets                uint32 // Number of tickets (t) - The number of tickets introduced by the validator.
	NumOfPreimages              uint32 // Number of preimages (p) - The number of preimages introduced by the validator.
	NumOfBytesAllPreimages      uint32 // Number of bytes across all preimages (d) - The total number of octets across all preimages introduced by the validator.
	NumOfGuaranteedReports      uint32 // Number of guaranteed reports (g) - The number of reports guaranteed by the validator.
	NumOfAvailabilityAssurances uint32 // Number of availability assurances (a) - The number of assurances of availability made by the validator.
}

// UnmarshalJAM implements the JAM codec Unmarshaler interface.
func (vs *ValidatorStatistics) UnmarshalJAM(r io.Reader) error {
	buf := make([]byte, 24)
	if _, err := io.ReadFull(r, buf); err != nil {
		return err
	}
	vs.NumOfBlocks = jam.DecodeUint32(buf[0:4])
	vs.NumOfTickets = jam.DecodeUint32(buf[4:8])
	vs.NumOfPreimages = jam.DecodeUint32(buf[8:12])
	vs.NumOfBytesAllPreimages = jam.DecodeUint32(buf[12:16])
	vs.NumOfGuaranteedReports = jam.DecodeUint32(buf[16:20])
	vs.NumOfAvailabilityAssurances = jam.DecodeUint32(buf[20:24])
	return nil
}

type CoreStatistics struct {
	// DALoad (d) is the amount of bytes placed into either Audits or Segments DA.
	// This includes the work-bundle (including all extrinsics and imports) as well as all
	// (exported) segments.
	DALoad         uint32 `jam:"encoding=compact"`
	Popularity     uint16 `jam:"encoding=compact"` // Popularity (p) is the number of validators which formed super-majority for assurance.
	Imports        uint16 `jam:"encoding=compact"` // Imports (i) is the number of segments imported from DA made by core for reported work.
	ExtrinsicCount uint16 `jam:"encoding=compact"` // ExtrinsicCount (z) is the total number of extrinsics used by core for reported work.
	ExtrinsicSize  uint32 `jam:"encoding=compact"` // ExtrinsicSize (x) is the total size of extrinsics used by core for reported work.
	Exports        uint16 `jam:"encoding=compact"` // Exports (e) is the number of segments exported into DA made by core for reported work.
	BundleSize     uint32 `jam:"encoding=compact"` // BundleSize (b) is the work-bundle size. This is the size of data being placed into Audits DA by the core.
	GasUsed        uint64 `jam:"encoding=compact"` // GasUsed (g) is the total gas consumed by core for reported work. Includes all refinement and authorizations.
}

type ServiceActivityRecord struct {
	ProvidedCount     uint16 `jam:"encoding=compact"` // ProvidedCount (p.0) is the number of preimages provided to this service.
	ProvidedSize      uint32 `jam:"encoding=compact"` // ProvidedSize (p.1) is the total size of preimages provided to this service.
	RefinementCount   uint32 `jam:"encoding=compact"` // RefinementCount (r.0) is the number of work-items refined by service for reported work.
	RefinementGasUsed uint64 `jam:"encoding=compact"` // RefinementGasUsed (r.1) is the amount of gas used for refinement by service for reported work.
	Imports           uint32 `jam:"encoding=compact"` // Imports (i) is the number of segments imported from the DL by service for reported work.
	ExtrinsicCount    uint32 `jam:"encoding=compact"` // ExtrinsicCount (z) is the total number of extrinsics used by service for reported work.
	ExtrinsicSize     uint32 `jam:"encoding=compact"` // ExtrinsicSize (x) is the total size of extrinsics used by service for reported work.
	Exports           uint32 `jam:"encoding=compact"` // Exports (e) is the number of segments exported into the DL by service for reported work.
	AccumulateCount   uint32 `jam:"encoding=compact"` // AccumulateCount (a.0) is the number of work-items accumulated by service.
	AccumulateGasUsed uint64 `jam:"encoding=compact"` // AccumulateGasUsed (a.1) is the amount of gas used for accumulation by service.
}

type ServiceStatistics map[block.ServiceId]ServiceActivityRecord

// NullifyOffenders implements equation 6.14 from the graypaper, i.e Φ(k). If any of the queued
// validator data matches the offenders list (ψ′_o), all the keys for that
// validator are zero'd out. v0.7.0
func NullifyOffenders(queuedValidators safrole.ValidatorsData, offenders []ed25519.PublicKey) (safrole.ValidatorsData, []ed25519.PublicKey) {
	offenderMap := make(crypto.ED25519PublicKeySet)
	nullifiedKeys := make([]ed25519.PublicKey, 0, len(offenders))
	for _, key := range offenders {
		offenderMap.Add(key)
	}
	for i, validator := range queuedValidators {
		if offenderMap.Has(validator.Ed25519) {
			queuedValidators[i] = crypto.ValidatorKey{
				// Ensure these 32 bytes are zero'd out, and not just nil.
				Ed25519: ed25519.ZeroPublicKey,
			} // Nullify the validator.
			nullifiedKeys = append(nullifiedKeys, validator.Ed25519)
		}
	}
	return queuedValidators, nullifiedKeys
}
