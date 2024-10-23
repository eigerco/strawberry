package state

// Import necessary packages
import (
	"log"

	"github.com/eigerco/strawberry/internal/block"
	"github.com/eigerco/strawberry/internal/jamtime"
)

// State represents the complete state of the system
type State struct {
	Services                 ServiceState             // Service accounts mapping (δ)
	PrivilegedServices       PrivilegedServices       // Privileged services (𝝌): services which hold some privileged status.
	ValidatorState           ValidatorState           // Validator related state (κ, λ, ι, γ)
	EntropyPool              EntropyPool              // On-chain Entropy pool (η): pool of entropy accumulators (also called randomness accumulators).
	CoreAuthorizersPool      CoreAuthorizersPool      // Core authorizers pool (α): authorization requirement which work done on that core must satisfy at the time of being reported on-chain.
	PendingAuthorizersQueues PendingAuthorizersQueues // Pending Core authorizers queue (φ): the queue which fills core authorizations.
	CoreAssignments          CoreAssignments          // Core assignments (ρ): each of the cores’ currently assigned report, the availability of whose work-package must yet be assured by a super-majority of validators. This is what each core is up to right now, tracks the work-reports which have been reported but not yet accumulated, the identities of the guarantors who reported them and the time at which it was reported.
	RecentBlocks             []BlockState             // Block-related state (β): details of the most recent blocks. TODO: Maximum length: MaxRecentBlocks
	TimeslotIndex            jamtime.Timeslot         // Time-related state (τ): the most recent block’s slot index.
	PastJudgements           Judgements               // PastJudgements (ψ) - past judgements on work-reports and validators.
	ValidatorStatistics      ValidatorStatisticsState // Validator statistics (π) - The activity statistics for the validators.
	AccumulationQueue        AccumulationQueue        // Accumulation Queue (ϑ) - ready (i.e. available and/or audited) but not-yet-accumulated work-reports. Each of these were made available at most one epoch ago but have or had unfulfilled dependencies.
	AccumulationHistory      AccumulationHistory      // Accumulation history (ξ) - history of what has been accumulated for an epoch worth of work-reports. Mapping of work-package hash to segment-root.
}

// UpdateState updates the state
// TODO: all the calculations which are not dependent on intermediate / new state can be done in parallel
//
//	it might be worth making State immutable and make it so that UpdateState returns a new State with all the updated fields
func (s *State) UpdateState(newBlock block.Block) {
	// Calculate newSafroleState state values

	newTimeState := calculateNewTimeState(newBlock.Header)

	newValidatorStatistics := calculateNewValidatorStatistics(newBlock.Extrinsic, s.TimeslotIndex, newTimeState, s.ValidatorStatistics)

	intermediateCoreAssignments := calculateIntermediateCoreAssignmentsFromExtrinsics(newBlock.Extrinsic.ED, s.CoreAssignments)
	intermediateCoreAssignments = calculateIntermediateCoreAssignmentsFromAvailability(newBlock.Extrinsic.EA, intermediateCoreAssignments)
	newCoreAssignments := calculateNewCoreAssignments(newBlock.Extrinsic.EG, intermediateCoreAssignments, s.ValidatorState, newTimeState)

	intermediateServiceState := calculateIntermediateServiceState(newBlock.Extrinsic.EP, s.Services, newTimeState)
	newServices, newPrivilegedServices, newQueuedValidators, newPendingCoreAuthorizations, context := calculateServiceState(
		newBlock.Extrinsic.EA,
		newCoreAssignments,
		intermediateServiceState,
		s.PrivilegedServices,
		s.ValidatorState.QueuedValidators,
		s.PendingAuthorizersQueues,
	)

	intermediateRecentBlocks := calculateIntermediateBlockState(newBlock.Header, s.RecentBlocks)
	newRecentBlocks, err := calculateNewRecentBlocks(newBlock.Header, newBlock.Extrinsic.EG, intermediateRecentBlocks, context)
	if err != nil {
		// TODO handle error
		log.Printf("Error calculating new Recent Blocks: %v", err)
	}

	newEntropyPool, err := calculateNewEntropyPool(newBlock.Header, s.TimeslotIndex, s.EntropyPool)
	if err != nil {
		// TODO handle error
		log.Printf("Error calculating new Entropy pool: %v", err)
	} else {
		s.EntropyPool = newEntropyPool
	}

	newJudgements := calculateNewJudgements(newBlock.Extrinsic.ED, s.PastJudgements)

	newCoreAuthorizations := calculateNewCoreAuthorizations(newBlock.Extrinsic.EG, newPendingCoreAuthorizations, s.CoreAuthorizersPool)

	newValidators, err := calculateNewValidators(newBlock.Header, s.TimeslotIndex, s.ValidatorState.CurrentValidators, s.ValidatorState.SafroleState.NextValidators)
	if err != nil {
		// TODO handle error
		log.Printf("Error calculating new Validators: %v", err)
	} else {
		s.ValidatorState.CurrentValidators = newValidators
	}

	newArchivedValidators, err := calculateNewArchivedValidators(newBlock.Header, s.TimeslotIndex, s.ValidatorState.ArchivedValidators, s.ValidatorState.CurrentValidators)
	if err != nil {
		// TODO handle error
		log.Printf("Error calculating new Archived Validators: %v", err)
	} else {
		s.ValidatorState.ArchivedValidators = newArchivedValidators
	}

	newSafroleState, err := calculateNewSafroleState(newBlock.Header, s.TimeslotIndex, newBlock.Extrinsic.ET, s.ValidatorState.QueuedValidators)
	if err != nil {
		// TODO handle error
		log.Printf("Error calculating new Safrole state: %v", err)
	} else {
		s.ValidatorState.SafroleState = newSafroleState
	}

	// Update the state with newSafroleState values
	s.TimeslotIndex = newTimeState
	s.ValidatorStatistics = newValidatorStatistics
	s.RecentBlocks = newRecentBlocks
	s.CoreAssignments = newCoreAssignments
	s.PastJudgements = newJudgements
	s.CoreAuthorizersPool = newCoreAuthorizations
	s.ValidatorState.QueuedValidators = newQueuedValidators
	s.Services = newServices
	s.PrivilegedServices = newPrivilegedServices
}
