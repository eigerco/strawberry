package validator

import (
	"crypto/ed25519"

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

// ValidatorStatisticsState represents the statistics related to validators.
type ValidatorStatisticsState [2][common.NumberOfValidators]ValidatorStatistics // Completed statistics (π[0]) - The activity statistics for the validators which have completed their work. Present statistics (π[1]) - The activity statistics for the validators which are currently being accumulated.

type ValidatorStatistics struct {
	NumOfBlocks                 uint32 // Number of blocks (b) - The number of blocks produced by the validator.
	NumOfTickets                uint64 // Number of tickets (t) - The number of tickets introduced by the validator.
	NumOfPreimages              uint64 // Number of preimages (p) - The number of preimages introduced by the validator.
	NumOfBytesAllPreimages      uint64 // Number of bytes across all preimages (d) - The total number of octets across all preimages introduced by the validator.
	NumOfGuaranteedReports      uint64 // Number of guaranteed reports (g) - The number of reports guaranteed by the validator.
	NumOfAvailabilityAssurances uint64 // Number of availability assurances (a) - The number of assurances of availability made by the validator.
}

// Implements equation 59 from the graypaper, i.e Φ(k). If any of the queued
// validator data matches the offenders list (ψ′), all the keys for that
// validator are zero'd out.
func NullifyOffenders(queuedValidators safrole.ValidatorsData, offenders []ed25519.PublicKey) safrole.ValidatorsData {
	offenderMap := make(map[string]struct{})
	for _, key := range offenders {
		offenderMap[string(key)] = struct{}{}
	}
	for i, validator := range queuedValidators {
		if _, found := offenderMap[string(validator.Ed25519)]; found {
			queuedValidators[i] = &crypto.ValidatorKey{
				// Ensure these 32 bytes are zero'd out, and not just nil.  TODO
				// - maybe use a custom wrapper type for [32]byte ?
				Ed25519: make([]byte, 32),
			} // Nullify the validator.
		}
	}
	return queuedValidators
}
