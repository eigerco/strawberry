package state

import (
	"github.com/eigerco/strawberry/internal/safrole"
	"github.com/eigerco/strawberry/internal/time"
)

// TODO: These calculations are just mocks for now. They will be replaced with actual calculations when the state transitions are implemented.

// Intermediate State Calculation Functions

// calculateIntermediateBlockState Equation 17: β† ≺ (H, β)
func calculateIntermediateBlockState(header Header, previousRecentBlocks []BlockState) []BlockState {
	return []BlockState{}
}

// calculateIntermediateServiceState Equation 24: δ† ≺ (EP, δ, τ′)
func calculateIntermediateServiceState(preimages Preimages, serviceState ServiceState, timeslot time.Timeslot) ServiceState {
	return make(ServiceState)
}

// calculateIntermediateCoreAssignmentsFromExtrinsics Equation 25: ρ† ≺ (EV , ρ)
func calculateIntermediateCoreAssignmentsFromExtrinsics(extrinsics Extrinsics, coreAssignments CoreAssignments) CoreAssignments {
	return CoreAssignments{}
}

// calculateIntermediateCoreAssignmentsFromAvailability Equation 26: ρ‡ ≺ (EA, ρ†)
func calculateIntermediateCoreAssignmentsFromAvailability(availability Availability, coreAssignments CoreAssignments) CoreAssignments {
	return CoreAssignments{}
}

// Final State Calculation Functions

// calculateNewTimeState Equation 16: τ′ ≺ H
func calculateNewTimeState(header Header) time.Timeslot {
	return header.TimeslotIndex
}

// calculateNewRecentBlocks Equation 18: β′ ≺ (H, EG, β†, C)
func calculateNewRecentBlocks(header Header, reports Reports, intermediateRecentBlocks []BlockState, context Context) []BlockState {
	return []BlockState{}
}

// calculateNewSafroleState Equation 19: γ′ ≺ (H, τ, ET , γ, ι, η′, κ′)
func calculateNewSafroleState(header Header, timeslot time.Timeslot, tickets Tickets, nextValidators safrole.ValidatorsData, queuedValidators safrole.ValidatorsData, newEntropyPool EntropyPool, newValidators safrole.ValidatorsData) safrole.State {
	return safrole.State{}
}

// calculateNewEntropyPool Equation 20: η′ ≺ (H, τ, η)
func calculateNewEntropyPool(header Header, timeslot time.Timeslot, entropyPool EntropyPool) EntropyPool {
	return EntropyPool{}
}

// calculateNewCoreAuthorizations Equation 29: α' ≺ (EG, φ', α)
func calculateNewCoreAuthorizations(reports Reports, pendingCoreAuthorizations PendingAuthorizersQueues, coreAuthorizations CoreAuthorizersPool) CoreAuthorizersPool {
	return CoreAuthorizersPool{}
}

// calculateNewValidators Equation 21: κ′ ≺ (H, τ, κ, γ, ψ′)
func calculateNewValidators(header Header, timeslot time.Timeslot, validators safrole.ValidatorsData, nextValidators safrole.ValidatorsData, judgements Judgements) safrole.ValidatorsData {
	return safrole.ValidatorsData{}
}

// calculateNewJudgements Equation 23: ψ′ ≺ (EV, ψ)
func calculateNewJudgements(extrinsicsJudgements Judgements, stateJudgements Judgements) Judgements {
	return Judgements{}
}

// calculateNewCoreAssignments Equation 27: ρ′ ≺ (EG, ρ‡, κ, τ′)
func calculateNewCoreAssignments(reports Reports, coreAssignments CoreAssignments, validators safrole.ValidatorsData, timeslot time.Timeslot) CoreAssignments {
	return CoreAssignments{}
}

// calculateNewArchivedValidators Equation 22: λ′ ≺ (H, τ, λ, κ)
func calculateNewArchivedValidators(header Header, timeslot time.Timeslot, archivedValidators safrole.ValidatorsData, validators safrole.ValidatorsData) safrole.ValidatorsData {
	return safrole.ValidatorsData{}
}

// calculateServiceState Equation 28: δ′, 𝝌′, ι′, φ′, C ≺ (EA, ρ′, δ†, 𝝌, ι, φ)
func calculateServiceState(availability Availability, coreAssignments CoreAssignments, intermediateServiceState ServiceState, privilegedServices PrivilegedServices, queuedValidators safrole.ValidatorsData, coreAuthorizationQueue PendingAuthorizersQueues) (ServiceState, PrivilegedServices, safrole.ValidatorsData, PendingAuthorizersQueues, Context) {
	return make(ServiceState), PrivilegedServices{}, safrole.ValidatorsData{}, PendingAuthorizersQueues{}, Context{}
}

// calculateNewValidatorStatistics Equation 30: π′ ≺ (EG, EP, EA, ET, τ, τ′, π)
func calculateNewValidatorStatistics(extrinsics Extrinsics, timeslot time.Timeslot, newTimeSlot time.Timeslot, validatorStatistics ValidatorStatisticsState) ValidatorStatisticsState {
	return ValidatorStatisticsState{}
}
