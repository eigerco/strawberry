package state

import (
	"github.com/eigerco/strawberry/internal/block"
	"github.com/eigerco/strawberry/internal/jamtime"
	"github.com/eigerco/strawberry/internal/safrole"
)

// ValidatorState represents the state related to validators
type ValidatorState struct {
	Validators         safrole.ValidatorsData // Validators mapping (κ) (identified)
	ArchivedValidators safrole.ValidatorsData // Archived validators (λ) (archived)
	QueuedValidators   safrole.ValidatorsData // Queue of validators to be added (ι) (enqueued)
	SafroleState       safrole.State          // Safrole State (𝛾) (state of block-production algorithm)
}

// ValidatorStatisticsState represents the statistics related to validators.
type ValidatorStatisticsState [2]ValidatorStatistics // Completed statistics (π[0]) - The activity statistics for the validators which have completed their work. Present statistics (π[1]) - The activity statistics for the validators which are currently being accumulated.

type ValidatorStatistics struct {
	NumOfBlocks                 uint32 // Number of blocks (n) - The number of blocks produced by the validator.
	NumOfTickets                uint64 // Number of tickets (t) - The number of tickets introduced by the validator.
	NumOfPreimages              uint64 // Number of preimages (p) - The number of preimages introduced by the validator.
	NumOfBytesAllPreimages      uint64 // Number of bytes across all preimages (d) - The total number of octets across all preimages introduced by the validator.
	NumOfGuaranteedReports      uint64 // Number of guaranteed reports (g) - The number of reports guaranteed by the validator.
	NumOfAvailabilityAssurances uint64 // Number of availability assurances (a) - The number of assurances of availability made by the validator.
}

// TODO do we need to clear the TicketAccumulator when the epoch changes or is it part of state transition?
// Should be called when a new block is produced to update the sealing keys
func (vs *ValidatorState) UpdateSealingKeys(newBlock *block.Block) error {
    newKeys, err := safrole.DetermineNewSealingKeys(
        jamtime.Timeslot(newBlock.Header.TimeSlotIndex),
        vs.SafroleState.TicketAccumulator,
        vs.SafroleState.SealingKeySeries,
        newBlock.Header.EpochMarker,
    )
    if err != nil {
        return err
    }
    vs.SafroleState.SealingKeySeries = newKeys
    return nil
}
