package state

// Import necessary packages
import (
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
}

// UpdateState updates the state
// TODO: all the calculations which are not dependent on intermediate / new state can be done in parallel
//
//	it might be worth making State immutable and make it so that UpdateState returns a new State with all the updated fields
func (s *State) UpdateState(newBlock block.Block) {
	// Calculate newSafroleState state values

	newTimeState := calculateNewTimeState(*newBlock.Header)

	newValidatorStatistics := calculateNewValidatorStatistics(*newBlock.Extrinsic, s.TimeslotIndex, newTimeState, s.ValidatorStatistics)

	intermediateCoreAssignments := calculateIntermediateCoreAssignmentsFromExtrinsics(*newBlock.Extrinsic.ED, s.CoreAssignments)
	intermediateCoreAssignments = calculateIntermediateCoreAssignmentsFromAvailability(*newBlock.Extrinsic.EA, intermediateCoreAssignments)
	newCoreAssignments := calculateNewCoreAssignments(*newBlock.Extrinsic.EG, intermediateCoreAssignments, s.ValidatorState.Validators, newTimeState)

	intermediateServiceState := calculateIntermediateServiceState(*newBlock.Extrinsic.EP, s.Services, newTimeState)
	newServices, newPrivilegedServices, newQueuedValidators, newPendingCoreAuthorizations, context := calculateServiceState(
		*newBlock.Extrinsic.EA,
		newCoreAssignments,
		intermediateServiceState,
		s.PrivilegedServices,
		s.ValidatorState.QueuedValidators,
		s.PendingAuthorizersQueues,
	)

	intermediateRecentBlocks := calculateIntermediateBlockState(*newBlock.Header, s.RecentBlocks)
	newRecentBlocks := calculateNewRecentBlocks(*newBlock.Header, *newBlock.Extrinsic.EG, intermediateRecentBlocks, context)

	newEntropyPool := calculateNewEntropyPool(*newBlock.Header, s.TimeslotIndex, s.EntropyPool)

	newJudgements := calculateNewJudgements(*newBlock.Extrinsic.ED, s.PastJudgements)

	newCoreAuthorizations := calculateNewCoreAuthorizations(*newBlock.Extrinsic.EG, newPendingCoreAuthorizations, s.CoreAuthorizersPool)

	newValidators := calculateNewValidators(*newBlock.Header, s.TimeslotIndex, s.ValidatorState.Validators, s.ValidatorState.SafroleState.NextValidators, newJudgements)

	newSafroleState := calculateNewSafroleState(*newBlock.Header, s.TimeslotIndex, *newBlock.Extrinsic.ET, s.ValidatorState.SafroleState.NextValidators, s.ValidatorState.QueuedValidators, newEntropyPool, newValidators)

	newArchivedValidators := calculateNewArchivedValidators(*newBlock.Header, s.TimeslotIndex, s.ValidatorState.ArchivedValidators, s.ValidatorState.Validators)

	// Update the state with newSafroleState values

	s.TimeslotIndex = newTimeState
	s.ValidatorStatistics = newValidatorStatistics
	s.RecentBlocks = newRecentBlocks
	s.CoreAssignments = newCoreAssignments
	s.EntropyPool = newEntropyPool
	s.PastJudgements = newJudgements
	s.CoreAuthorizersPool = newCoreAuthorizations
	s.ValidatorState.SafroleState = newSafroleState
	s.ValidatorState.ArchivedValidators = newArchivedValidators
	s.ValidatorState.Validators = newValidators
	s.ValidatorState.QueuedValidators = newQueuedValidators
	s.Services = newServices
	s.PrivilegedServices = newPrivilegedServices
}
