package state

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"

	"github.com/eigerco/strawberry/internal/block"
	"github.com/eigerco/strawberry/internal/common"
	"github.com/eigerco/strawberry/internal/crypto"
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
func calculateNewSafroleState(header block.Header, timeslot jamtime.Timeslot, tickets block.TicketExtrinsic, queuedValidators safrole.ValidatorsData) (safrole.State, error) {
	if !header.TimeSlotIndex.IsFirstTimeslotInEpoch() {
		return safrole.State{}, errors.New("not first timeslot in epoch")
	}
	validTickets := block.ExtractTicketFromProof(tickets.TicketProofs)
	newSafrole := safrole.State{}
	newNextValidators := nullifyOffenders(queuedValidators, header.OffendersMarkers)
	ringCommitment := CalculateRingCommitment(newNextValidators)
	newSealingKeySeries, err := safrole.DetermineNewSealingKeys(timeslot, validTickets, safrole.TicketsOrKeys{}, header.EpochMarker)
	if err != nil {
		return safrole.State{}, err
	}
	newSafrole.NextValidators = newNextValidators
	newSafrole.RingCommitment = ringCommitment
	newSafrole.SealingKeySeries = newSealingKeySeries
	return newSafrole, nil
}

// calculateNewEntropyPool Equation 20: η′ ≺ (H, τ, η)
func calculateNewEntropyPool(header block.Header, timeslot jamtime.Timeslot, entropyPool EntropyPool) (EntropyPool, error) {
	newEntropyPool := entropyPool
	vrfOutput, err := extractVRFOutput(header)
	if err != nil {
		return EntropyPool{}, err
	}
	newEntropy := crypto.Hash(append(entropyPool[0][:], vrfOutput[:]...))
	if header.TimeSlotIndex.IsFirstTimeslotInEpoch() {
		newEntropyPool = rotateEntropyPool(entropyPool)
	}
	newEntropyPool[0] = newEntropy
	return newEntropyPool, nil
}

// calculateNewCoreAuthorizations Equation 29: α' ≺ (EG, φ', α)
func calculateNewCoreAuthorizations(guarantees block.GuaranteesExtrinsic, pendingCoreAuthorizations PendingAuthorizersQueues, coreAuthorizations CoreAuthorizersPool) CoreAuthorizersPool {
	return CoreAuthorizersPool{}
}

// calculateNewValidators Equation 21: κ′ ≺ (H, τ, κ, γ, ψ′)
func calculateNewValidators(header block.Header, timeslot jamtime.Timeslot, validators safrole.ValidatorsData, nextValidators safrole.ValidatorsData) (safrole.ValidatorsData, error) {
	if !header.TimeSlotIndex.IsFirstTimeslotInEpoch() {
		return validators, errors.New("not first timeslot in epoch")
	}
	return nextValidators, nil
}

// addUniqueHash adds a hash to a slice if it's not already present
func addUniqueHash(slice []crypto.Hash, hash crypto.Hash) []crypto.Hash {
	for _, v := range slice {
		if v == hash {
			return slice
		}
	}
	return append(slice, hash)
}

// addUniqueEdPubKey adds a public key to a slice if it's not already present
func addUniqueEdPubKey(slice []ed25519.PublicKey, key ed25519.PublicKey) []ed25519.PublicKey {
	for _, v := range slice {
		if bytes.Equal(v, key) {
			return slice
		}
	}
	return append(slice, key)
}

// processVerdict categorizes a verdict based on positive judgments. Equations 111, 112, 113.
func processVerdict(judgements *Judgements, verdict block.Verdict) {
	positiveJudgments := 0
	for _, judgment := range verdict.Judgements {
		if judgment.IsValid {
			positiveJudgments++
		}
	}

	switch positiveJudgments {
	// Equation 111: ψ'g ≡ ψg ∪ {r | {r, ⌊2/3V⌋ + 1} ∈ V}
	case block.ValidatorsSuperMajority:
		judgements.GoodWorkReports = addUniqueHash(judgements.GoodWorkReports, verdict.ReportHash)
		// Equation 112: ψ'b ≡ ψb ∪ {r | {r, 0} ∈ V}
	case 0:
		judgements.BadWorkReports = addUniqueHash(judgements.BadWorkReports, verdict.ReportHash)
		// Equation 113: ψ'w ≡ ψw ∪ {r | {r, ⌊1/3V⌋} ∈ V}
	case common.NumberOfValidators / 3:
		judgements.WonkyWorkReports = addUniqueHash(judgements.WonkyWorkReports, verdict.ReportHash)
		// TODO: The GP gives only the above 3 cases. Check back later how can we be sure only the above 3 cases are possible.
	default:
		panic(fmt.Sprintf("Unexpected number of positive judgments: %d", positiveJudgments))
	}
}

// processOffender adds an offending validator to the list
func processOffender(judgements *Judgements, key ed25519.PublicKey) {
	judgements.OffendingValidators = addUniqueEdPubKey(judgements.OffendingValidators, key)
}

// calculateNewJudgements Equation 23: ψ′ ≺ (ED, ψ)
func calculateNewJudgements(disputes block.DisputeExtrinsic, stateJudgements Judgements) Judgements {
	newJudgements := Judgements{
		BadWorkReports:      make([]crypto.Hash, len(stateJudgements.BadWorkReports)),
		GoodWorkReports:     make([]crypto.Hash, len(stateJudgements.GoodWorkReports)),
		WonkyWorkReports:    make([]crypto.Hash, len(stateJudgements.WonkyWorkReports)),
		OffendingValidators: make([]ed25519.PublicKey, len(stateJudgements.OffendingValidators)),
	}

	copy(newJudgements.BadWorkReports, stateJudgements.BadWorkReports)
	copy(newJudgements.GoodWorkReports, stateJudgements.GoodWorkReports)
	copy(newJudgements.WonkyWorkReports, stateJudgements.WonkyWorkReports)
	copy(newJudgements.OffendingValidators, stateJudgements.OffendingValidators)

	// Process verdicts (Equations 111, 112, 113)
	for _, verdict := range disputes.Verdicts {
		processVerdict(&newJudgements, verdict)
	}

	// Process culprits and faults (Equation 114)
	for _, culprit := range disputes.Culprits {
		processOffender(&newJudgements, culprit.ValidatorEd25519PublicKey)
	}
	for _, fault := range disputes.Faults {
		processOffender(&newJudgements, fault.ValidatorEd25519PublicKey)
	}

	return newJudgements
}

// calculateNewCoreAssignments Equation 27: ρ′ ≺ (EG, ρ‡, κ, τ′)
func calculateNewCoreAssignments(guarantees block.GuaranteesExtrinsic, coreAssignments CoreAssignments, validators safrole.ValidatorsData, timeslot jamtime.Timeslot) CoreAssignments {
	return CoreAssignments{}
}

// calculateNewArchivedValidators Equation 22: λ′ ≺ (H, τ, λ, κ)
func calculateNewArchivedValidators(header block.Header, timeslot jamtime.Timeslot, archivedValidators safrole.ValidatorsData, validators safrole.ValidatorsData) (safrole.ValidatorsData, error) {
	if !header.TimeSlotIndex.IsFirstTimeslotInEpoch() {
		return archivedValidators, errors.New("not first timeslot in epoch")
	}
	return validators, nil
}

// calculateServiceState Equation 28: δ′, 𝝌′, ι′, φ′, C ≺ (EA, ρ′, δ†, 𝝌, ι, φ)
func calculateServiceState(assurances block.AssurancesExtrinsic, coreAssignments CoreAssignments, intermediateServiceState ServiceState, privilegedServices PrivilegedServices, queuedValidators safrole.ValidatorsData, coreAuthorizationQueue PendingAuthorizersQueues) (ServiceState, PrivilegedServices, safrole.ValidatorsData, PendingAuthorizersQueues, Context) {
	return make(ServiceState), PrivilegedServices{}, safrole.ValidatorsData{}, PendingAuthorizersQueues{}, Context{}
}

// calculateNewValidatorStatistics Equation 30: π′ ≺ (EG, EP, EA, ET, τ, τ′, π)
func calculateNewValidatorStatistics(extrinsics block.Extrinsic, timeslot jamtime.Timeslot, newTimeSlot jamtime.Timeslot, validatorStatistics ValidatorStatisticsState) ValidatorStatisticsState {
	return ValidatorStatisticsState{}
}
