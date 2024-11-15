package statetransition

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/eigerco/strawberry/internal/polkavm/invocations"
	"log"
	"maps"
	"slices"
	"sort"
	"sync"

	"github.com/eigerco/strawberry/internal/block"
	"github.com/eigerco/strawberry/internal/common"
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/jamtime"
	"github.com/eigerco/strawberry/internal/polkavm"
	"github.com/eigerco/strawberry/internal/safrole"
	"github.com/eigerco/strawberry/internal/service"
	"github.com/eigerco/strawberry/internal/state"
	"github.com/eigerco/strawberry/internal/validator"
)

const (
	signatureContextGuarantee = "$jam_guarantee"
)

// UpdateState updates the state
// TODO: all the calculations which are not dependent on intermediate / new state can be done in parallel
//
//	it might be worth making State immutable and make it so that UpdateState returns a new State with all the updated fields
func UpdateState(s *state.State, newBlock block.Block) {
	// Calculate newSafroleState state values

	newTimeState := calculateNewTimeState(newBlock.Header)

	newValidatorStatistics := calculateNewValidatorStatistics(newBlock, newTimeState, s.ValidatorStatistics)

	intermediateCoreAssignments := calculateIntermediateCoreAssignmentsFromExtrinsics(newBlock.Extrinsic.ED, s.CoreAssignments)
	intermediateCoreAssignments = calculateIntermediateCoreAssignmentsFromAvailability(newBlock.Extrinsic.EA, intermediateCoreAssignments)
	newCoreAssignments := calculateNewCoreAssignments(newBlock.Extrinsic.EG, intermediateCoreAssignments, s.ValidatorState, newTimeState)

	intermediateServiceState := calculateIntermediateServiceState(newBlock.Extrinsic.EP, s.Services, newTimeState)

	newAccumulationQueue,
		newAccumulationHistory,
		newServices,
		newPrivilegedServices,
		newQueuedValidators,
		newPendingCoreAuthorizations,
		serviceHashPairs := calculateWorkReportsAndAccumulate(
		newBlock.Header,
		s.TimeslotIndex,
		newTimeState,
		newBlock.Extrinsic.EA,
		newCoreAssignments,
		s.AccumulationQueue,
		s.AccumulationHistory,
		intermediateServiceState,
		s.PrivilegedServices,
		s.ValidatorState.QueuedValidators,
		s.PendingAuthorizersQueues,
	)

	intermediateRecentBlocks := calculateIntermediateBlockState(newBlock.Header, s.RecentBlocks)
	newRecentBlocks, err := calculateNewRecentBlocks(newBlock.Header, newBlock.Extrinsic.EG, intermediateRecentBlocks, serviceHashPairs)
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

	newCoreAuthorizations := calculateNewCoreAuthorizations(newBlock.Header, newBlock.Extrinsic.EG, newPendingCoreAuthorizations, s.CoreAuthorizersPool)

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
	s.AccumulationQueue = newAccumulationQueue
	s.AccumulationHistory = newAccumulationHistory
}

// Intermediate State Calculation Functions

// calculateIntermediateBlockState Equation 17: β† ≺ (H, β)
func calculateIntermediateBlockState(header block.Header, previousRecentBlocks []state.BlockState) []state.BlockState {
	intermediateBlocks := make([]state.BlockState, len(previousRecentBlocks))

	// Copy all elements from previousRecentBlocks to intermediateBlocks
	copy(intermediateBlocks, previousRecentBlocks)

	// Update the state root of the most recent block
	if len(intermediateBlocks) > 0 {
		lastIndex := len(intermediateBlocks) - 1
		intermediateBlocks[lastIndex].StateRoot = header.PriorStateRoot
	}

	return intermediateBlocks
}

// calculateIntermediateServiceState Equation 24: δ† ≺ (EP, δ, τ′)
// This function calculates the intermediate service state δ† based on:
// - The current service state δ (serviceState)
// - The preimage extrinsic EP (preimages)
// - The new timeslot τ′ (newTimeslot)
//
// For each preimage in EP:
//  1. It adds the preimage p to the PreimageLookup of service s, keyed by its hash H(p)
//  2. It adds a new entry to the PreimageMeta of service s, keyed by the hash H(p) and
//     length |p|, with the value being the new timeslot τ′
//
// The function returns a new ServiceState without modifying the input state.
func calculateIntermediateServiceState(preimages block.PreimageExtrinsic, serviceState service.ServiceState, newTimeslot jamtime.Timeslot) service.ServiceState {
	// Equation 156:
	// δ† = δ ex. ∀⎧⎩s, p⎫⎭ ∈ EP:
	// ⎧ δ†[s]p[H(p)] = p
	// ⎩ δ†[s]l[H(p), |p|] = [τ′]

	// Shallow copy of the entire state
	newState := make(service.ServiceState, len(serviceState))
	for k, v := range serviceState {
		newState[k] = v
	}

	for _, preimage := range preimages {
		serviceId := block.ServiceId(preimage.ServiceIndex)
		account, exists := newState[serviceId]
		if !exists {
			continue
		}

		preimageHash := crypto.HashData(preimage.Data)
		preimageLength := service.PreimageLength(len(preimage.Data))

		// Check conditions from equation 155
		// Eq. 155: ∀⎧⎩s, p⎫⎭ ∈ EP : K(δ[s]p) ∌ H(p) ∧ δ[s]l[⎧⎩H(p), |p|⎫⎭] = []
		// For all preimages: hash not in lookup and no existing metadata
		if _, exists := account.PreimageLookup[preimageHash]; exists {
			continue // Skip if preimage already exists
		}
		metaKey := service.PreImageMetaKey{Hash: preimageHash, Length: preimageLength}
		if existingMeta, exists := account.PreimageMeta[metaKey]; exists && len(existingMeta) > 0 {
			continue // Skip if metadata already exists and is not empty
		}

		// If checks pass, add the new preimage
		if account.PreimageLookup == nil {
			account.PreimageLookup = make(map[crypto.Hash][]byte)
		}
		account.PreimageLookup[preimageHash] = preimage.Data

		if account.PreimageMeta == nil {
			account.PreimageMeta = make(map[service.PreImageMetaKey]service.PreimageHistoricalTimeslots)
		}
		account.PreimageMeta[metaKey] = []jamtime.Timeslot{newTimeslot}

		newState[serviceId] = account
	}

	return newState
}

// calculateIntermediateCoreAssignmentsFromExtrinsics Equation 25: ρ† ≺ (ED , ρ)
func calculateIntermediateCoreAssignmentsFromExtrinsics(disputes block.DisputeExtrinsic, coreAssignments state.CoreAssignments) state.CoreAssignments {
	newAssignments := coreAssignments // Create a copy of the current assignments

	// Process each verdict in the disputes
	for _, verdict := range disputes.Verdicts {
		reportHash := verdict.ReportHash
		positiveJudgments := block.CountPositiveJudgments(verdict.Judgements)

		// If less than 2/3 majority of positive judgments, clear the assignment for matching cores
		if positiveJudgments < common.ValidatorsSuperMajority {
			for c := uint16(0); c < common.TotalNumberOfCores; c++ {
				if newAssignments[c].WorkReport != nil {
					if hash, err := newAssignments[c].WorkReport.Hash(); err == nil && hash == reportHash {
						newAssignments[c] = state.Assignment{} // Clear the assignment
					}
				}
			}
		}
	}

	return newAssignments
}

// calculateIntermediateCoreAssignmentsFromAvailability implements equation 26: ρ‡ ≺ (EA, ρ†)
// It calculates the intermediate core assignments based on availability assurances.
func calculateIntermediateCoreAssignmentsFromAvailability(assurances block.AssurancesExtrinsic, coreAssignments state.CoreAssignments) state.CoreAssignments {
	// Initialize availability count for each core
	availabilityCounts := make([]int, common.TotalNumberOfCores)

	// Process each assurance in the AssurancesExtrinsic (EA)
	for _, assurance := range assurances {
		// Check the availability status for each core in this assurance
		for coreIndex := uint16(0); coreIndex < common.TotalNumberOfCores; coreIndex++ {
			// Calculate which byte and bit within the Bitfield correspond to this core
			byteIndex := coreIndex / 8
			bitIndex := coreIndex % 8

			// Check if the bit corresponding to this core is set (1) in the Bitfield
			if assurance.Bitfield[byteIndex]&(1<<bitIndex) != 0 {
				// If set, increment the availability count for this core
				availabilityCounts[coreIndex]++
			}
		}
	}

	// Create new CoreAssignments (ρ‡)
	var newAssignments state.CoreAssignments

	// Calculate the availability threshold (2/3 of validators)
	// This implements part of equation 129: ∑a∈EA av[c] > 2/3 V
	availabilityThreshold := (2 * common.NumberOfValidators) / 3

	// Update assignments based on availability
	// This implements equation 130: ∀c ∈ NC : ρ‡[c] ≡ { ∅ if ρ[c]w ∈ W, ρ†[c] otherwise }
	for coreIndex := uint16(0); coreIndex < common.TotalNumberOfCores; coreIndex++ {
		if availabilityCounts[coreIndex] > availabilityThreshold {
			// If the availability count exceeds the threshold, keep the assignment
			// This corresponds to ρ[c]w ∈ W in equation 129
			newAssignments[coreIndex] = coreAssignments[coreIndex]
		} else {
			// If the availability count doesn't exceed the threshold, clear the assignment
			// This corresponds to the ∅ case in equation 130
			newAssignments[coreIndex] = state.Assignment{}
		}
	}

	// Return the new intermediate CoreAssignments (ρ‡)
	return newAssignments
}

// Final State Calculation Functions

// calculateNewTimeState Equation 16: τ′ ≺ H
func calculateNewTimeState(header block.Header) jamtime.Timeslot {
	return header.TimeSlotIndex
}

// calculateNewRecentBlocks Equation 18: β′ ≺ (H, EG, β†, C) v0.4.5
func calculateNewRecentBlocks(header block.Header, guarantees block.GuaranteesExtrinsic, intermediateRecentBlocks []state.BlockState, serviceHashPairs ServiceHashPairs) ([]state.BlockState, error) {
	// Equation 83: let r = M_B([s ^^ E_4(s) ⌢ E(h) | (s, h) ∈ C], H_K)
	accumulationRoot := calculateAccumulationRoot(serviceHashPairs)

	// Equation 83: let b = A(last([[]] ⌢ [x_b | x <− β]), r, H_K)
	var lastBlockMMR crypto.Hash
	if len(intermediateRecentBlocks) > 0 {
		lastBlockMMR = intermediateRecentBlocks[len(intermediateRecentBlocks)-1].AccumulationResultMMR
	}
	newMMR := AppendToMMR(lastBlockMMR, accumulationRoot)

	// Equation 83: p = {((g_w)_s)_h ↦ ((g_w)_s)_e | g ∈ E_G}
	workPackageMapping := buildWorkPackageMapping(guarantees.Guarantees)

	// Equation 83: let n = {p, h ▸▸ H(H), b, s ▸▸ H_0}
	headerBytes, err := json.Marshal(header)
	if err != nil {
		return nil, err
	}
	newBlockState := state.BlockState{
		HeaderHash:            crypto.HashData(headerBytes), // h ▸▸ H(H)
		StateRoot:             crypto.Hash{},                // s ▸▸ H_0
		AccumulationResultMMR: newMMR,                       // b
		WorkReportHashes:      workPackageMapping,           // p
	}

	// Equation 84: β′ ≡ ←────── β† n_H
	// First append new block state
	newRecentBlocks := append(intermediateRecentBlocks, newBlockState)

	// Then keep only last H blocks
	if len(newRecentBlocks) > state.MaxRecentBlocks {
		newRecentBlocks = newRecentBlocks[len(newRecentBlocks)-state.MaxRecentBlocks:]
	}

	return newRecentBlocks, nil
}

// TODO: this is just a mock implementation
func AppendToMMR(lastBlockMMR crypto.Hash, accumulationRoot crypto.Hash) crypto.Hash {
	return crypto.Hash{}
}

// TODO: this is just a mock implementation
// This should create a Merkle tree from the accumulations and return the root
func calculateAccumulationRoot(accumulations ServiceHashPairs) crypto.Hash {
	return crypto.Hash{}
}

// buildWorkPackageMapping creates the work package mapping p from equation 83:
// p = {((gw)s)h ↦ ((gw)s)e | g ∈ EG}
func buildWorkPackageMapping(guarantees []block.Guarantee) map[crypto.Hash]crypto.Hash {
	workPackages := make(map[crypto.Hash]crypto.Hash)
	for _, g := range guarantees {
		workPackages[g.WorkReport.WorkPackageSpecification.WorkPackageHash] =
			g.WorkReport.WorkPackageSpecification.SegmentRoot
	}
	return workPackages
}

// calculateNewSafroleState Equation 19: γ′ ≺ (H, τ, ET , γ, ι, η′, κ′)
func calculateNewSafroleState(header block.Header, timeslot jamtime.Timeslot, tickets block.TicketExtrinsic, queuedValidators safrole.ValidatorsData) (safrole.State, error) {
	if !header.TimeSlotIndex.IsFirstTimeslotInEpoch() {
		return safrole.State{}, errors.New("not first timeslot in epoch")
	}
	validTickets := block.ExtractTicketFromProof(tickets.TicketProofs)
	newSafrole := safrole.State{}
	newNextValidators := validator.NullifyOffenders(queuedValidators, header.OffendersMarkers)
	ringCommitment := validator.CalculateRingCommitment(newNextValidators)
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
func calculateNewEntropyPool(header block.Header, timeslot jamtime.Timeslot, entropyPool state.EntropyPool) (state.EntropyPool, error) {
	newEntropyPool := entropyPool
	vrfOutput, err := state.ExtractVRFOutput(header)
	if err != nil {
		return state.EntropyPool{}, err
	}
	newEntropy := crypto.Hash(append(entropyPool[0][:], vrfOutput[:]...))
	if header.TimeSlotIndex.IsFirstTimeslotInEpoch() {
		newEntropyPool = state.RotateEntropyPool(entropyPool)
	}
	newEntropyPool[0] = newEntropy
	return newEntropyPool, nil
}

// calculateNewCoreAuthorizations implements equation 29: α' ≺ (H, EG, φ', α)
func calculateNewCoreAuthorizations(header block.Header, guarantees block.GuaranteesExtrinsic, pendingAuthorizations state.PendingAuthorizersQueues, currentAuthorizations state.CoreAuthorizersPool) state.CoreAuthorizersPool {
	var newCoreAuthorizations state.CoreAuthorizersPool

	// For each core
	for c := uint16(0); c < common.TotalNumberOfCores; c++ {
		// Start with the existing authorizations for this core
		newAuths := make([]crypto.Hash, len(currentAuthorizations[c]))
		copy(newAuths, currentAuthorizations[c])

		// F(c) - Remove authorizer if it was used in a guarantee for this core
		for _, guarantee := range guarantees.Guarantees {
			if guarantee.WorkReport.CoreIndex == c {
				// Remove the used authorizer from the list
				newAuths = removeAuthorizer(newAuths, guarantee.WorkReport.AuthorizerHash)
			}
		}

		// Get new authorizer from the queue based on current timeslot
		// φ'[c][Ht]↺O - Get authorizer from queue, wrapping around queue size
		queueIndex := header.TimeSlotIndex % state.PendingAuthorizersQueueSize
		newAuthorizer := pendingAuthorizations[c][queueIndex]

		// Only add new authorizer if it's not empty
		if newAuthorizer != (crypto.Hash{}) {
			// ← Append new authorizer maintaining max size O
			newAuths = appendAuthorizerLimited(newAuths, newAuthorizer, state.MaxAuthorizersPerCore)
		}

		// Store the new authorizations for this core
		newCoreAuthorizations[c] = newAuths
	}

	return newCoreAuthorizations
}

// removeAuthorizer removes an authorizer from a list while maintaining order
func removeAuthorizer(auths []crypto.Hash, toRemove crypto.Hash) []crypto.Hash {
	for i := 0; i < len(auths); i++ {
		if auths[i] == toRemove {
			// Remove by shifting remaining elements left
			copy(auths[i:], auths[i+1:])
			return auths[:len(auths)-1]
		}
	}
	return auths
}

// appendAuthorizerLimited appends a new authorizer while maintaining max size limit
// This implements the "←" (append limited) operator from the paper
func appendAuthorizerLimited(auths []crypto.Hash, newAuth crypto.Hash, maxSize int) []crypto.Hash {
	// If at max size, remove oldest (leftmost) element
	if len(auths) >= maxSize {
		copy(auths, auths[1:])
		auths = auths[:len(auths)-1]
	}

	// Append new authorizer
	return append(auths, newAuth)
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
func processVerdict(judgements *state.Judgements, verdict block.Verdict) {
	positiveJudgments := 0
	for _, judgment := range verdict.Judgements {
		if judgment.IsValid {
			positiveJudgments++
		}
	}

	switch positiveJudgments {
	// Equation 111: ψ'g ≡ ψg ∪ {r | {r, ⌊2/3V⌋ + 1} ∈ V}
	case common.ValidatorsSuperMajority:
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
func processOffender(judgements *state.Judgements, key ed25519.PublicKey) {
	judgements.OffendingValidators = addUniqueEdPubKey(judgements.OffendingValidators, key)
}

// calculateNewJudgements Equation 23: ψ′ ≺ (ED, ψ)
func calculateNewJudgements(disputes block.DisputeExtrinsic, stateJudgements state.Judgements) state.Judgements {
	newJudgements := state.Judgements{
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

// calculateNewCoreAssignments updates the core assignments based on new guarantees.
// This implements equation 27: ρ′ ≺ (EG, ρ‡, κ, τ′)
//
// It also implements part of equation 139 regarding timeslot validation:
// R(⌊τ′/R⌋ - 1) ≤ t ≤ τ′
func calculateNewCoreAssignments(
	guarantees block.GuaranteesExtrinsic,
	intermediateAssignments state.CoreAssignments,
	validatorState validator.ValidatorState,
	newTimeslot jamtime.Timeslot,
) state.CoreAssignments {
	newAssignments := intermediateAssignments
	sortedGuarantees := sortGuaranteesByCoreIndex(guarantees.Guarantees)

	for _, guarantee := range sortedGuarantees {
		coreIndex := guarantee.WorkReport.CoreIndex

		// Check timeslot range: R(⌊τ′/R⌋ - 1) ≤ t ≤ τ′
		previousRotationStart := (newTimeslot/common.ValidatorRotationPeriod - 1) * common.ValidatorRotationPeriod
		if guarantee.Timeslot < jamtime.Timeslot(previousRotationStart) ||
			guarantee.Timeslot > newTimeslot {
			continue
		}

		if isAssignmentValid(intermediateAssignments[coreIndex], newTimeslot) {
			// Determine which validator set to use based on timeslots
			validators := determineValidatorSet(
				guarantee.Timeslot,
				newTimeslot,
				validatorState.CurrentValidators,
				validatorState.ArchivedValidators,
			)

			if verifyGuaranteeCredentials(guarantee, validators) {
				newAssignments[coreIndex] = state.Assignment{
					WorkReport: &guarantee.WorkReport,
					Time:       newTimeslot,
				}
			}
		}
	}

	return newAssignments
}

// determineValidatorSet implements validator set selection from equations 135 and 139:
// From equation 139:
//
//	(c, k) = {
//	    G if ⌊τ′/R⌋ = ⌊t/R⌋
//	    G* otherwise
//
// Where G* is determined by equation 135:
//
//	let (e, k) = {
//	    (η′2, κ′) if ⌊τ′/R⌋ = ⌊τ′/E⌋
//	    (η′3, λ′) otherwise
func determineValidatorSet(
	guaranteeTimeslot jamtime.Timeslot,
	currentTimeslot jamtime.Timeslot,
	currentValidators safrole.ValidatorsData,
	archivedValidators safrole.ValidatorsData,
) safrole.ValidatorsData {
	currentRotation := currentTimeslot / common.ValidatorRotationPeriod
	guaranteeRotation := guaranteeTimeslot / common.ValidatorRotationPeriod

	if currentRotation == guaranteeRotation {
		return currentValidators
	}
	return archivedValidators
}

// sortGuaranteesByCoreIndex sorts the guarantees by their core index in ascending order.
// This implements equation 137 from the graypaper: EG = [(gw)c ^ g ∈ EG]
// which ensures that guarantees are ordered by core index.
func sortGuaranteesByCoreIndex(guarantees []block.Guarantee) []block.Guarantee {
	sortedGuarantees := make([]block.Guarantee, len(guarantees))
	copy(sortedGuarantees, guarantees)

	sort.Slice(sortedGuarantees, func(i, j int) bool {
		return sortedGuarantees[i].WorkReport.CoreIndex < sortedGuarantees[j].WorkReport.CoreIndex
	})

	return sortedGuarantees
}

// isAssignmentValid checks if a new assignment can be made for a core.
// This implements the condition from equation 142:
// ρ‡[wc] = ∅ ∨ Ht ≥ ρ‡[wc]t + U
func isAssignmentValid(currentAssignment state.Assignment, newTimeslot jamtime.Timeslot) bool {
	return currentAssignment.WorkReport == nil ||
		newTimeslot >= currentAssignment.Time+common.WorkReportTimeoutPeriod
}

// verifyGuaranteeCredentials verifies the credentials of a guarantee.
// This implements two equations from the graypaper:
//
// Equation 138: ∀g ∈ EG : ga = [v _ {v, s} ∈ ga]
// Which ensures credentials are ordered by validator index
//
//	Equation 139: ∀(w, t, a) ∈ EG, ∀(v, s) ∈ a : {
//	    s ∈ Ek[v]E⟨XG ⌢ H(E(w))⟩
//	    cv = wc
//	}
func verifyGuaranteeCredentials(guarantee block.Guarantee, validators safrole.ValidatorsData) bool {
	// Verify that credentials are ordered by validator index (equation 138)
	for i := 1; i < len(guarantee.Credentials); i++ {
		if guarantee.Credentials[i-1].ValidatorIndex >= guarantee.Credentials[i].ValidatorIndex {
			return false
		}
	}

	// Verify the signatures using the correct validator keys (equation 139)
	for _, credential := range guarantee.Credentials {
		if credential.ValidatorIndex >= uint16(len(validators)) {
			return false
		}

		// Check if the validator is assigned to the core specified in the work report
		if !isValidatorAssignedToCore(credential.ValidatorIndex, guarantee.WorkReport.CoreIndex, validators) {
			return false
		}

		validatorKey := validators[credential.ValidatorIndex]
		// Check if the validator key is valid
		if len(validatorKey.Ed25519) != ed25519.PublicKeySize {
			return false
		}
		reportBytes, err := json.Marshal(guarantee.WorkReport)
		if err != nil {
			return false
		}
		hashed := crypto.HashData(reportBytes)
		message := append([]byte(signatureContextGuarantee), hashed[:]...)
		if !ed25519.Verify(validatorKey.Ed25519, message, credential.Signature[:]) {
			return false
		}
	}

	return true
}

// TODO: This function should implement the logic to check if the validator is assigned to the core
// For now, it's a placeholder implementation
func isValidatorAssignedToCore(validatorIndex uint16, coreIndex uint16, validators safrole.ValidatorsData) bool {
	return true
}

// calculateNewArchivedValidators Equation 22: λ′ ≺ (H, τ, λ, κ)
func calculateNewArchivedValidators(header block.Header, timeslot jamtime.Timeslot, archivedValidators safrole.ValidatorsData, validators safrole.ValidatorsData) (safrole.ValidatorsData, error) {
	if !header.TimeSlotIndex.IsFirstTimeslotInEpoch() {
		return archivedValidators, errors.New("not first timeslot in epoch")
	}
	return validators, nil
}

// calculateWorkReportsAndAccumulate Equation 28: W* ≺ (EA, ρ′) and Equation 29: δ′, 𝝌′, ι′, φ′, C ≺ (EA, ρ′, δ†, 𝝌, ι, φ)
func calculateWorkReportsAndAccumulate(
	header block.Header,
	currentTimeslot jamtime.Timeslot,
	newTimeslot jamtime.Timeslot,
	assurances block.AssurancesExtrinsic,
	coreAssignments state.CoreAssignments,
	accQueue state.AccumulationQueue,
	accHistory state.AccumulationHistory,
	intermediateServiceState service.ServiceState,
	privilegedServices service.PrivilegedServices,
	queuedValidators safrole.ValidatorsData,
	coreAuthorizationQueue state.PendingAuthorizersQueues,
) (
	newAccumulationQueue state.AccumulationQueue,
	newAccumulationHistory state.AccumulationHistory,
	newServiceState service.ServiceState,
	newPrivilegedServices service.PrivilegedServices,
	newValidatorKeys safrole.ValidatorsData,
	newWorkReportsQueue state.PendingAuthorizersQueues,
	hashPairs ServiceHashPairs,
) {
	// TODO (156) ∀w ∈ w, ∀r ∈ wr ∶ rc = δ[rs]c
	// Ensure all service code hashes match
	//var expectedCodeHash *crypto.Hash
	//for _, report := range workReports {
	//	for _, result := range report.WorkResults {
	//		if result.ServiceId == serviceIndex {
	//			if expectedCodeHash == nil {
	//				expectedCodeHash = &result.ServiceHashCode
	//			} else if *expectedCodeHash != result.ServiceHashCode {
	//				return nil, 0, fmt.Errorf("inconsistent service code hash for service %d", serviceIndex)
	//			}
	//		}
	//	}
	//}

	//TODO (166) WQ ≡ E([D(w) S w <− W, (wx)p ≠ ∅ ∨ wl ≠ {}], {ξ)
	var queuedWorkReports []state.WorkReportWithUnAccumulatedDependencies

	//TODO (165) W! ≡ [w S w <− W, (wx)p = ∅ ∧ wl = {}]
	// var immediatelyAccWorkReports []block.WorkReport

	// let m = Ht mod E
	timeslotPerEpoch := header.TimeSlotIndex % jamtime.TimeslotsPerEpoch

	//TODO (172) W* ≡ W! ⌢ Q(q)
	// (173) where q = E(ϑm... ⌢ ϑ...m ⌢ WQ, P(W!))
	var accumulatableWorkReports []block.WorkReport

	// TODO let g = max(GT , GA ⋅ C + [∑ x∈V](χg)(x))
	gasLimit := uint64(0)

	// (182) let (n, o, t, C) = ∆+(g, W∗, (χ, δ†, ι, φ), χg )
	maxReports, newAccumulationState, transfers, hashPairs := SequentialDelta(gasLimit, accumulatableWorkReports, state.AccumulationState{
		PrivilegedServices: privilegedServices,
		ServiceState:       intermediateServiceState,
		ValidatorKeys:      queuedValidators,
		WorkReportsQueue:   coreAuthorizationQueue,
	}, privilegedServices)

	// (183) (χ′, δ‡, ι′, φ′) ≡ o
	postAccumulationServiceState := newAccumulationState.ServiceState
	newPrivilegedServices = newAccumulationState.PrivilegedServices
	newValidatorKeys = newAccumulationState.ValidatorKeys
	newWorkReportsQueue = newAccumulationState.WorkReportsQueue

	// (185) δ′ = {s ↦ ΨT (δ‡, s, R(t, s)) S (s ↦ a) ∈ δ‡}
	newServiceState = make(service.ServiceState)
	for serviceId := range postAccumulationServiceState {
		newService := invocations.InvokeOnTransfer(
			postAccumulationServiceState,
			serviceId,
			transfersForReceiver(transfers, serviceId),
		)
		newServiceState[serviceId] = newService
	}

	// (186) ξ′E−1 = P(W*...n)
	// (187) ∀i ∈ NE−1 ∶ ξ′i ≡ ξi+1
	newAccumulationHistory = state.AccumulationHistory(append(
		accHistory[1:],
		getWorkPackageHashes(accumulatableWorkReports[:maxReports]),
	))

	// ξ′E−1
	lastAccumulation := newAccumulationHistory[jamtime.TimeslotsPerEpoch-1]

	// (188) ∀i ∈ N_E
	for i := range jamtime.TimeslotsPerEpoch {
		indexPerEpoch := (timeslotPerEpoch - jamtime.Timeslot(i)) % jamtime.TimeslotsPerEpoch

		if i == 0 { // if i = 0
			// ϑ′↺m−i ≡ E(WQ, ξ′E−1)
			newAccumulationQueue[indexPerEpoch] = updateQueue(queuedWorkReports, lastAccumulation)
		} else if 1 <= i && jamtime.Timeslot(i) < newTimeslot-currentTimeslot { // if 1 ≤ i < τ ′ − τ
			// ϑ′↺m−i ≡ []
			newAccumulationQueue[indexPerEpoch] = []state.WorkReportWithUnAccumulatedDependencies{}
		} else if jamtime.Timeslot(i) >= newTimeslot-currentTimeslot { // if i ≥ τ ′ − τ
			// ϑ′↺m−i ≡ E(ϑ↺m−i, ξ′E−1)
			newAccumulationQueue[indexPerEpoch] = updateQueue(accQueue[indexPerEpoch], lastAccumulation)
		}
	}

	return newAccumulationQueue,
		newAccumulationHistory,
		newServiceState,
		newPrivilegedServices,
		newValidatorKeys,
		newWorkReportsQueue,
		hashPairs
}

// updateQueue (168) E(r ⟦(W, {H})⟧, x {H}) → ⟦(W, {H})⟧
func updateQueue(workRepAndDep []state.WorkReportWithUnAccumulatedDependencies, hashSet map[crypto.Hash]struct{}) []state.WorkReportWithUnAccumulatedDependencies {
	var newWorkRepsAndDeps []state.WorkReportWithUnAccumulatedDependencies
	for _, wd := range workRepAndDep {
		if _, ok := hashSet[wd.WorkReport.WorkPackageSpecification.WorkPackageHash]; !ok {
			dependencies := maps.Clone(wd.Dependencies)
			for hash := range hashSet {
				delete(dependencies, hash)
			}
			newWorkRepsAndDeps = append(newWorkRepsAndDeps, state.WorkReportWithUnAccumulatedDependencies{
				WorkReport:   wd.WorkReport,
				Dependencies: dependencies,
			})
		}
	}
	return newWorkRepsAndDeps
}

// (170) P(w {W}) → {H}
func getWorkPackageHashes(workReports []block.WorkReport) (hashes map[crypto.Hash]struct{}) {
	hashes = make(map[crypto.Hash]struct{})
	// {(ws)h S w ∈ w}
	for _, workReport := range workReports {
		hashes[workReport.WorkPackageSpecification.WorkPackageHash] = struct{}{}
	}
	return hashes
}

// transfersForReceiver (184) R(t ⟦T⟧, d NS ) → ⟦T⟧
func transfersForReceiver(transfers []service.DeferredTransfer, serviceId block.ServiceId) (transfersForReceiver []service.DeferredTransfer) {
	// [ t | t <− t, t_d = d ]
	for _, transfer := range transfers {
		if transfer.ReceiverServiceIndex == serviceId {
			transfersForReceiver = append(transfersForReceiver, transfer)
		}
	}

	// [ t | s <− N_S, t_s = s ]
	slices.SortStableFunc(transfersForReceiver, func(a, b service.DeferredTransfer) int {
		if a.SenderServiceIndex < b.SenderServiceIndex {
			return -1
		} else if a.SenderServiceIndex > b.SenderServiceIndex {
			return 1
		}
		return 0
	})
	return transfersForReceiver
}

// verifyAvailability implements availability verification part of equations 29-30:
// This function ensures cores have sufficient availability (>2/3 validators)
// before allowing accumulation
//
//lint:ignore U1000
func verifyAvailability(assurances block.AssurancesExtrinsic, assignments state.CoreAssignments) state.CoreAssignments {
	var availableCores state.CoreAssignments

	// Count assurances per core
	assuranceCounts := make([]int, common.TotalNumberOfCores)
	for _, assurance := range assurances {
		for coreIndex := uint16(0); coreIndex < common.TotalNumberOfCores; coreIndex++ {
			byteIndex := coreIndex / 8
			bitIndex := coreIndex % 8
			if (assurance.Bitfield[byteIndex] & (1 << bitIndex)) != 0 {
				assuranceCounts[coreIndex]++
			}
		}
	}

	// Only include cores with sufficient assurances
	for coreIndex := uint16(0); coreIndex < common.TotalNumberOfCores; coreIndex++ {
		if assuranceCounts[coreIndex] > (2 * common.NumberOfValidators / 3) {
			availableCores[coreIndex] = assignments[coreIndex]
		}
	}

	return availableCores
}

// processServiceTransitions implements equations 165-168:
// Equation 165: New service indices must not conflict
//
//	∀s ∈ S: K(A(s)n) ∩ K(δ†) = ∅,
//	∀t ∈ S ∖ {s}: K(A(s)n) ∩ K(A(t)n) = ∅
//
// Equation 166: Intermediate state after main accumulation
//
//	K(δ‡) ≡ K(δ†) ∪ ⋃s∈S K(A(s)n) ∖ {s | s ∈ S, ss = ∅}
//	δ‡[s] ≡ {
//	  A(s)s          if s ∈ S
//	  A(t)n[s]       if ∃!t: t ∈ S, s ∈ K(A(t)n)
//	  δ†[s]          otherwise
//	}
//
// Equation 167: Mapping of transfers received by each service
//
//	R: NS → ⟦T⟧
//	d ↦ [t | s <- S, t <- A(s)t, td = d]
//
// Equation 168: Final state after applying deferred transfers
//
//	δ′ = {s ↦ ΨT(δ‡, a, R(a)) | (s ↦ a) ∈ δ‡}
//
//lint:ignore U1000
func processServiceTransitions(accumResults map[block.ServiceId]state.AccumulationResult,
	intermediateState service.ServiceState) service.ServiceState {

	newState := make(service.ServiceState)
	// Copy existing state
	for k, v := range intermediateState {
		newState[k] = v
	}

	// Process each accumulation result
	for serviceId, result := range accumResults {
		// Handle updated service state
		if result.ServiceState != nil {
			newState[serviceId] = *result.ServiceState
		}

		// Add new services (equation 165)
		for newId, newAccount := range result.NewServices {
			if _, exists := intermediateState[newId]; !exists {
				newState[newId] = newAccount
			}
		}
	}

	return newState
}

// processPrivilegedTransitions implements equation 164:
// χ′ ≡ A(χm)p
// φ′ ≡ A(χa)c
// ι′ ≡ A(χv)v
// Processes privileged service accumulation results to update:
// - Manager service (χm)
// - Authorizer service (χa)
// - Validator service (χv)
//
//lint:ignore U1000
func processPrivilegedTransitions(
	accumResults map[block.ServiceId]state.AccumulationResult,
	privileged service.PrivilegedServices,
	queuedValidators safrole.ValidatorsData,
	coreAuth state.PendingAuthorizersQueues,
) (service.PrivilegedServices, safrole.ValidatorsData, state.PendingAuthorizersQueues) {
	newPrivileged := privileged
	newValidators := queuedValidators
	newAuth := coreAuth

	// Process each accumulation result
	for _, result := range accumResults {
		// Update privileged services
		if result.PrivilegedUpdates.ManagerServiceId != 0 {
			newPrivileged.ManagerServiceId = result.PrivilegedUpdates.ManagerServiceId
		}
		if result.PrivilegedUpdates.AssignServiceId != 0 {
			newPrivileged.AssignServiceId = result.PrivilegedUpdates.AssignServiceId
		}
		if result.PrivilegedUpdates.DesignateServiceId != 0 {
			newPrivileged.DesignateServiceId = result.PrivilegedUpdates.DesignateServiceId
		}

		// Update validator keys if there are any updates
		if len(result.ValidatorUpdates) > 0 {
			newValidators = result.ValidatorUpdates
		}

		// Integrate core authorization updates - check if non-zero
		if result.CoreAssignments != (state.PendingAuthorizersQueues{}) {
			newAuth = result.CoreAssignments
		}
	}

	return newPrivileged, newValidators, newAuth
}

// translatePVMContext translates between PVM context and accumulation results
// Implements structure defined in equation 254 (AccumulateContext) and
// equation 162 (A: result mapping function)
//
//lint:ignore U1000
func translatePVMContext(ctx polkavm.AccumulateContext, root *crypto.Hash) state.AccumulationResult {
	sa := ctx.ServiceAccount()
	return state.AccumulationResult{
		ServiceState:      &sa,
		ValidatorUpdates:  ctx.AccumulationState.ValidatorKeys,
		DeferredTransfers: ctx.DeferredTransfers,
		AccumulationRoot:  root,
		CoreAssignments:   ctx.AccumulationState.WorkReportsQueue,
		NewServices:       ctx.AccumulationState.ServiceState,
		PrivilegedUpdates: struct {
			ManagerServiceId   block.ServiceId
			AssignServiceId    block.ServiceId
			DesignateServiceId block.ServiceId
			GasAssignments     map[block.ServiceId]uint64
		}{
			ManagerServiceId:   ctx.AccumulationState.PrivilegedServices.ManagerServiceId,
			AssignServiceId:    ctx.AccumulationState.PrivilegedServices.AssignServiceId,
			DesignateServiceId: ctx.AccumulationState.PrivilegedServices.DesignateServiceId,
			GasAssignments:     ctx.AccumulationState.PrivilegedServices.AmountOfGasPerServiceId,
		},
	}
}

// getAvailableWorkReports is a helper function to extract available work reports
// from core assignments. This implements part of W set extraction from equation 129:
// W ≡ [ρ†[c]w | c <- NC, Σa∈EA av[c] > 2/3 V]
func getAvailableWorkReports(coreAssignments state.CoreAssignments) []block.WorkReport {
	var reports []block.WorkReport
	for _, assignment := range coreAssignments {
		if assignment.WorkReport != nil {
			reports = append(reports, *assignment.WorkReport)
		}
	}
	return reports
}

// determineServicesToAccumulate implements equation 157:
// S ≡ {rs | w ∈ W, r ∈ wr} ∪ K(()χg)
// Determines set of services to accumulate from:
// - Work reports that became available
// - Privileged services
//
//lint:ignore U1000
func determineServicesToAccumulate(assignments state.CoreAssignments, privileged service.PrivilegedServices) []block.ServiceId {
	services := make(map[block.ServiceId]struct{})

	// Add services from work reports
	for _, assignment := range assignments {
		if assignment.WorkReport != nil {
			for _, result := range assignment.WorkReport.WorkResults {
				services[result.ServiceId] = struct{}{}
			}
		}
	}

	// Add privileged services
	for serviceId := range privileged.AmountOfGasPerServiceId {
		services[serviceId] = struct{}{}
	}

	result := make([]block.ServiceId, 0, len(services))
	for serviceId := range services {
		result = append(result, serviceId)
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i] < result[j]
	})
	return result
}

// calculateGasAllocations implements equation 158:
// G: NS → NG
// s ↦ Σw∈W Σr∈wr,rs=s δ†[s]g + ⌊rg · (GA - Σr∈wr δ†[rs]g) / Σr∈wr rg⌋
// Calculates gas allocations for each service based on:
// - Minimum required gas from service state
// - Proportional share of remaining gas based on work results
//
//lint:ignore U1000
func calculateGasAllocations(
	services []block.ServiceId,
	state service.ServiceState,
	coreAssignments state.CoreAssignments,
) map[block.ServiceId]uint64 {
	allocations := make(map[block.ServiceId]uint64)

	// Calculate total minimum gas required for all services
	totalMinGas := uint64(0)
	for _, serviceId := range services {
		if account, exists := state[serviceId]; exists {
			totalMinGas += account.GasLimitForAccumulator
			// Initialize with minimum required gas
			allocations[serviceId] = account.GasLimitForAccumulator
		}
	}

	// Calculate remaining gas after minimum allocations
	if totalMinGas >= service.CoreGasAccumulation {
		return allocations
	}
	remainingGas := service.CoreGasAccumulation - totalMinGas

	// Calculate sum of gas ratios for all work results
	totalGasRatios := uint64(0)
	gasRatiosByService := make(map[block.ServiceId]uint64)

	// Get work results for each service
	for _, assignment := range coreAssignments {
		if assignment.WorkReport != nil {
			for _, result := range assignment.WorkReport.WorkResults {
				for _, serviceId := range services {
					if result.ServiceId == serviceId {
						gasRatiosByService[serviceId] += result.GasPrioritizationRatio
						totalGasRatios += result.GasPrioritizationRatio
					}
				}
			}
		}
	}

	// Distribute remaining gas proportionally according to gas ratios
	if totalGasRatios > 0 {
		for serviceId, ratioSum := range gasRatiosByService {
			additionalGas := (ratioSum * remainingGas) / totalGasRatios
			allocations[serviceId] += additionalGas
		}
	}

	return allocations
}

// wrangleAccumulationOperands implements equations 159-160:
// Equation 159: O ≡ {o ∈ Y ∪ J, l ∈ H, k ∈ H, a ∈ Y}
// Equation 160: M: NS → ⟦O⟧
// Prepares accumulation operands from work reports by collecting:
// - Outputs or errors
// - Payload hashes
// - Work package hashes
// - Authorization outputs
//
//lint:ignore U1000
func wrangleAccumulationOperands(assignment state.CoreAssignments) map[block.ServiceId][]state.AccumulationOperand {
	mapping := make(map[block.ServiceId][]state.AccumulationOperand)

	// Process each work report
	for _, report := range getAvailableWorkReports(assignment) {
		// Process each work result in the report
		for _, result := range report.WorkResults {
			operand := state.AccumulationOperand{
				Output:              result.Output,
				PayloadHash:         result.PayloadHash,
				WorkPackageHash:     report.WorkPackageSpecification.WorkPackageHash,
				AuthorizationOutput: report.Output,
			}

			// Append to the service's operands sequence
			serviceId := result.ServiceId
			mapping[serviceId] = append(mapping[serviceId], operand)
		}
	}

	return mapping
}

// buildServiceAccumulationCommitments implements equation 163:
// C ≡ {(s, A(s)r) | s ∈ S, A(s)r ≠ ∅}
// Maps accumulated services to their accumulation result hashes
//
//lint:ignore U1000
func buildServiceAccumulationCommitments(accumResults map[block.ServiceId]state.AccumulationResult) map[block.ServiceId]crypto.Hash {
	commitments := make(map[block.ServiceId]crypto.Hash)

	for serviceId, result := range accumResults {
		// Only include services that have a non-empty accumulation root
		if result.AccumulationRoot != nil {
			commitments[serviceId] = *result.AccumulationRoot
		}
	}

	return commitments
}

// calculateNewValidatorStatistics implements equation 30:
// π′ ≺ (EG, EP, EA, ET, τ, κ′, π, H)
func calculateNewValidatorStatistics(block block.Block, currentTime jamtime.Timeslot, validatorStatistics validator.ValidatorStatisticsState) validator.ValidatorStatisticsState {
	newStats := validatorStatistics

	// Implements equations 170-171:
	// let e = ⌊τ/E⌋, e′ = ⌊τ′/E⌋
	// (a, π′₁) ≡ { (π₀, π₁) if e′ = e
	//              ([{0,...,[0,...]},...], π₀) otherwise
	if block.Header.TimeSlotIndex.IsFirstTimeslotInEpoch() {
		// Rotate statistics - completed stats become history, start fresh present stats
		newStats[0] = newStats[1]                                                // Move current to history
		newStats[1] = [common.NumberOfValidators]validator.ValidatorStatistics{} // Reset current
	}

	// Implements equation 172: ∀v ∈ NV
	for v := uint16(0); v < uint16(len(newStats)); v++ {
		// π′₀[v]b ≡ a[v]b + (v = Hi)
		if v == block.Header.BlockAuthorIndex {
			newStats[1][v].NumOfBlocks++

			// π′₀[v]t ≡ a[v]t + {|ET| if v = Hi
			//                     0 otherwise
			newStats[1][v].NumOfTickets += uint64(len(block.Extrinsic.ET.TicketProofs))

			// π′₀[v]p ≡ a[v]p + {|EP| if v = Hi
			//                     0 otherwise
			newStats[1][v].NumOfPreimages += uint64(len(block.Extrinsic.EP))

			// π′₀[v]d ≡ a[v]d + {Σd∈EP|d| if v = Hi
			//                     0 otherwise
			for _, preimage := range block.Extrinsic.EP {
				newStats[1][v].NumOfBytesAllPreimages += uint64(len(preimage.Data))
			}
		}

		// π′₀[v]g ≡ a[v]g + (κ′v ∈ R)
		// Where R is the set of reporter keys defined in eq 139
		for _, guarantee := range block.Extrinsic.EG.Guarantees {
			for _, credential := range guarantee.Credentials {
				if credential.ValidatorIndex == v {
					newStats[1][v].NumOfGuaranteedReports++
				}
			}
		}

		// π′₀[v]a ≡ a[v]a + (∃a ∈ EA : av = v)
		for _, assurance := range block.Extrinsic.EA {
			if assurance.ValidatorIndex == v {
				newStats[1][v].NumOfAvailabilityAssurances++
			}
		}
	}

	return newStats
}

// ServiceHashPairs (176) B ≡ {(NS , H)}
type ServiceHashPairs []ServiceHashPair

type ServiceHashPair struct {
	ServiceId block.ServiceId
	Hash      crypto.Hash
}

// SequentialDelta implements equation 177 (∆+)
func SequentialDelta(
	gasLimit uint64,
	workReports []block.WorkReport,
	ctx state.AccumulationState,
	privileged service.PrivilegedServices,
) (
	uint32,
	state.AccumulationState,
	[]service.DeferredTransfer,
	ServiceHashPairs,
) {
	// If no work reports, return early
	if len(workReports) == 0 {
		return 0, ctx, nil, ServiceHashPairs{}
	}

	// Calculate i = max(N|w|+1) : ∑w∈w...i∑r∈wr(rg) ≤ g
	maxReports := 0
	totalGas := uint64(0)

	// Sum up gas requirements until we exceed limit
	for i, report := range workReports {
		reportGas := uint64(0)
		for _, result := range report.WorkResults {
			reportGas += result.GasPrioritizationRatio
		}

		if totalGas+reportGas > gasLimit {
			break
		}

		totalGas += reportGas
		maxReports = i + 1
	}

	// If no reports can be processed, return early
	if maxReports == 0 {
		return 0, ctx, nil, ServiceHashPairs{}
	}

	// Process maxReports using ParallelDelta (∆*)
	gasUsed, newCtx, transfers, hashPairs := ParallelDelta(
		ctx,
		workReports[:maxReports],
		privileged.AmountOfGasPerServiceId,
	)

	// If we have remaining reports and gas, process recursively (∆+)
	if maxReports < len(workReports) {
		remainingGas := gasLimit - gasUsed
		if remainingGas > 0 {
			moreItems, finalCtx, moreTransfers, moreHashPairs := SequentialDelta(
				remainingGas,
				workReports[maxReports:],
				newCtx,
				privileged,
			)

			return uint32(maxReports) + moreItems,
				finalCtx,
				append(transfers, moreTransfers...),
				append(hashPairs, moreHashPairs...)
		}
	}

	return uint32(maxReports), newCtx, transfers, hashPairs
}

// ParallelDelta implements equation 178 (∆*)
func ParallelDelta(
	initialAccState state.AccumulationState,
	workReports []block.WorkReport,
	privilegedGas map[block.ServiceId]uint64, // D⟨NS → NG⟩
) (
	uint64, // total gas used
	state.AccumulationState, // updated context
	[]service.DeferredTransfer, // all transfers
	ServiceHashPairs, // accumulation outputs
) {
	// Get all unique service indices involved (s)
	// s = {rs S w ∈ w, r ∈ wr} ∪ K(f)
	serviceIndices := make(map[block.ServiceId]struct{})

	// From work reports
	for _, report := range workReports {
		for _, result := range report.WorkResults {
			serviceIndices[result.ServiceId] = struct{}{}
		}
	}

	// From privileged gas assignments
	for svcId := range privilegedGas {
		serviceIndices[svcId] = struct{}{}
	}

	var totalGasUsed uint64
	var allTransfers []service.DeferredTransfer
	accumHashPairs := make(ServiceHashPairs, 0)
	newAccState := state.AccumulationState{
		ServiceState: make(service.ServiceState),
	}

	var mu sync.Mutex
	var wg sync.WaitGroup

	for svcId := range serviceIndices {
		wg.Add(1)
		go func(serviceId block.ServiceId) {
			defer wg.Done()

			// Process single service using Delta1
			accState, deferredTransfers, resultHash, gasUsed := Delta1(initialAccState, workReports, privilegedGas, serviceId)
			mu.Lock()
			defer mu.Unlock()

			// Update total gas used
			totalGasUsed += gasUsed

			// Collect transfers
			if len(deferredTransfers) > 0 {
				allTransfers = append(allTransfers, deferredTransfers...)
			}

			// Store accumulation result if present
			if resultHash != nil {
				accumHashPairs = append(accumHashPairs, ServiceHashPair{
					ServiceId: serviceId,
					Hash:      *resultHash,
				})
			}

			// d′ = {s ↦ ds S s ∈ K(d) ∖ s} ∪ [⋃ s∈s] ((∆1(o, w, f , s)o)d
			for serviceId, serviceAccount := range accState.ServiceState {
				newAccState.ServiceState[serviceId] = serviceAccount
			}
		}(svcId)
	}

	wg.Add(1)
	go func(serviceId block.ServiceId) {
		defer wg.Done()

		// Process single service using Delta1
		accState, _, _, _ := Delta1(initialAccState, workReports, privilegedGas, serviceId)
		mu.Lock()
		defer mu.Unlock()

		newAccState.PrivilegedServices = accState.PrivilegedServices

	}(initialAccState.PrivilegedServices.ManagerServiceId)

	wg.Add(1)
	go func(serviceId block.ServiceId) {
		defer wg.Done()

		// Process single service using Delta1
		accState, _, _, _ := Delta1(initialAccState, workReports, privilegedGas, serviceId)
		mu.Lock()
		defer mu.Unlock()

		newAccState.ValidatorKeys = accState.ValidatorKeys

	}(initialAccState.PrivilegedServices.AssignServiceId)

	wg.Add(1)
	go func(serviceId block.ServiceId) {
		defer wg.Done()

		// Process single service using Delta1
		accState, _, _, _ := Delta1(initialAccState, workReports, privilegedGas, serviceId)
		mu.Lock()
		defer mu.Unlock()

		newAccState.WorkReportsQueue = accState.WorkReportsQueue

	}(initialAccState.PrivilegedServices.DesignateServiceId)

	// Wait for all goroutines to complete
	wg.Wait()

	// Sort accumulation pairs by service ID to ensure deterministic output
	sort.Slice(accumHashPairs, func(i, j int) bool {
		return accumHashPairs[i].ServiceId < accumHashPairs[j].ServiceId
	})

	return totalGasUsed, newAccState, allTransfers, accumHashPairs
}

// Delta1 implements equation 180 (∆1)
func Delta1(
	accumulationState state.AccumulationState,
	workReports []block.WorkReport,
	privilegedGas map[block.ServiceId]uint64, // D⟨NS → NG⟩
	serviceIndex block.ServiceId, // NS
) (state.AccumulationState, []service.DeferredTransfer, *crypto.Hash, uint64) {
	// Calculate gas limit (g)
	gasLimit := uint64(0)
	if gas, exists := privilegedGas[serviceIndex]; exists {
		gasLimit = gas
	}

	// Add gas from all relevant work items for this service
	for _, report := range workReports {
		for _, result := range report.WorkResults {
			if result.ServiceId == serviceIndex {
				gasLimit += result.GasPrioritizationRatio
			}
		}
	}

	// Collect work item operands (p)
	var operands []state.AccumulationOperand
	for _, report := range workReports {
		for _, result := range report.WorkResults {
			if result.ServiceId == serviceIndex {
				operand := state.AccumulationOperand{
					Output:              result.Output,
					PayloadHash:         result.PayloadHash,
					WorkPackageHash:     report.WorkPackageSpecification.WorkPackageHash,
					AuthorizationOutput: report.Output,
				}
				operands = append(operands, operand)
			}
		}
	}

	// TODO pass in state and header
	// Invoke VM for accumulation (ΨA)
	return invocations.NewAccumulator(nil, nil).Invoke(
		accumulationState,
		serviceIndex,
		gasLimit,
		operands,
	)
}
