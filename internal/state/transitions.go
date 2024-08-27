package state

import (
	"github.com/eigerco/strawberry/internal/block"
	"github.com/eigerco/strawberry/internal/jamtime"
	"github.com/eigerco/strawberry/internal/safrole"
)

// TODO: These calculations are just mocks for now. They will be replaced with actual calculations when the state transitions are implemented.

// Intermediate State Calculation Functions

// calculateIntermediateBlockState Equation 17: β† ≺ (H, β)
func calculateIntermediateBlockState(header block.Header, previousRecentBlocks []BlockState) []BlockState {
	return []BlockState{}
}

// calculateIntermediateServiceState Equation 24: δ† ≺ (EP, δ, τ′)
func calculateIntermediateServiceState(preimages block.PreimageExtrinsic, serviceState ServiceState, timeslot jamtime.Timeslot) ServiceState {
	return make(ServiceState)
}

// calculateIntermediateCoreAssignmentsFromExtrinsics Equation 25: ρ† ≺ (ED , ρ)
func calculateIntermediateCoreAssignmentsFromExtrinsics(disputes block.DisputeExtrinsic, coreAssignments CoreAssignments) CoreAssignments {
	return CoreAssignments{}
}

// calculateIntermediateCoreAssignmentsFromAvailability Equation 26: ρ‡ ≺ (EA, ρ†)
func calculateIntermediateCoreAssignmentsFromAvailability(assurances block.AssurancesExtrinsic, coreAssignments CoreAssignments) CoreAssignments {
	return CoreAssignments{}
}

// Final State Calculation Functions

// calculateNewTimeState Equation 16: τ′ ≺ H
func calculateNewTimeState(header block.Header) jamtime.Timeslot {
	return header.TimeSlotIndex
}

// calculateNewRecentBlocks Equation 18: β′ ≺ (H, EG, β†, C)
func calculateNewRecentBlocks(header block.Header, guarantees block.GuaranteesExtrinsic, intermediateRecentBlocks []BlockState, context Context) []BlockState {
	return []BlockState{}
}

// calculateNewSafroleState Equation 19: γ′ ≺ (H, τ, ET , γ, ι, η′, κ′)
func calculateNewSafroleState(header block.Header, timeslot jamtime.Timeslot, tickets block.TicketExtrinsic, nextValidators safrole.ValidatorsData, queuedValidators safrole.ValidatorsData, newEntropyPool EntropyPool, newValidators safrole.ValidatorsData) safrole.State {
	return safrole.State{}
}

// calculateNewEntropyPool Equation 20: η′ ≺ (H, τ, η)
func calculateNewEntropyPool(header block.Header, timeslot jamtime.Timeslot, entropyPool EntropyPool) EntropyPool {
	return EntropyPool{}
}

// calculateNewCoreAuthorizations Equation 29: α' ≺ (EG, φ', α)
func calculateNewCoreAuthorizations(guarantees block.GuaranteesExtrinsic, pendingCoreAuthorizations PendingAuthorizersQueues, coreAuthorizations CoreAuthorizersPool) CoreAuthorizersPool {
	return CoreAuthorizersPool{}
}

// calculateNewValidators Equation 21: κ′ ≺ (H, τ, κ, γ, ψ′)
func calculateNewValidators(header block.Header, timeslot jamtime.Timeslot, validators safrole.ValidatorsData, nextValidators safrole.ValidatorsData, judgements Judgements) safrole.ValidatorsData {
	return safrole.ValidatorsData{}
}

// calculateNewJudgements Equation 23: ψ′ ≺ (ED, ψ)
func calculateNewJudgements(disputes block.DisputeExtrinsic, stateJudgements Judgements) Judgements {
	return Judgements{}
}

// calculateNewCoreAssignments Equation 27: ρ′ ≺ (EG, ρ‡, κ, τ′)
func calculateNewCoreAssignments(guarantees block.GuaranteesExtrinsic, coreAssignments CoreAssignments, validators safrole.ValidatorsData, timeslot jamtime.Timeslot) CoreAssignments {
	return CoreAssignments{}
}

// calculateNewArchivedValidators Equation 22: λ′ ≺ (H, τ, λ, κ)
func calculateNewArchivedValidators(header block.Header, timeslot jamtime.Timeslot, archivedValidators safrole.ValidatorsData, validators safrole.ValidatorsData) safrole.ValidatorsData {
	return safrole.ValidatorsData{}
}

// calculateServiceState Equation 28: δ′, 𝝌′, ι′, φ′, C ≺ (EA, ρ′, δ†, 𝝌, ι, φ)
func calculateServiceState(assurances block.AssurancesExtrinsic, coreAssignments CoreAssignments, intermediateServiceState ServiceState, privilegedServices PrivilegedServices, queuedValidators safrole.ValidatorsData, coreAuthorizationQueue PendingAuthorizersQueues) (ServiceState, PrivilegedServices, safrole.ValidatorsData, PendingAuthorizersQueues, Context) {
	return make(ServiceState), PrivilegedServices{}, safrole.ValidatorsData{}, PendingAuthorizersQueues{}, Context{}
}

// calculateNewValidatorStatistics Equation 30: π′ ≺ (EG, EP, EA, ET, τ, τ′, π)
func calculateNewValidatorStatistics(extrinsics block.Extrinsic, timeslot jamtime.Timeslot, newTimeSlot jamtime.Timeslot, validatorStatistics ValidatorStatisticsState) ValidatorStatisticsState {
	return ValidatorStatisticsState{}
}
