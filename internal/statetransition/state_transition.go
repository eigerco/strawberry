package statetransition

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"
	"maps"
	"math"
	"slices"
	"sort"
	"sync"

	"github.com/eigerco/strawberry/internal/assuring"
	"github.com/eigerco/strawberry/internal/block"
	"github.com/eigerco/strawberry/internal/common"
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/disputing"
	"github.com/eigerco/strawberry/internal/guaranteeing"
	"github.com/eigerco/strawberry/internal/jamtime"
	"github.com/eigerco/strawberry/internal/merkle/binary_tree"
	"github.com/eigerco/strawberry/internal/merkle/mountain_ranges"
	"github.com/eigerco/strawberry/internal/polkavm"
	"github.com/eigerco/strawberry/internal/safrole"
	"github.com/eigerco/strawberry/internal/service"
	"github.com/eigerco/strawberry/internal/state"
	"github.com/eigerco/strawberry/internal/state/serialization/statekey"
	"github.com/eigerco/strawberry/internal/store"
	"github.com/eigerco/strawberry/internal/validator"
	"github.com/eigerco/strawberry/pkg/serialization/codec/jam"
)

// UpdateState updates the state
// TODO: all the calculations which are not dependent on intermediate / new state can be done in parallel
//
//	it might be worth making State immutable and make it so that UpdateState returns a new State with all the updated fields
func UpdateState(s *state.State, newBlock block.Block, chain *store.Chain, trie *store.Trie) error {
	err := VerifyBlockHeaderBasic(s, newBlock, trie)
	if err != nil {
		return fmt.Errorf("failed to verify block header: %w", err)
	}

	prevTimeSlot := s.TimeslotIndex
	newTimeSlot := CalculateNewTimeState(newBlock.Header)

	intermediateRecentHistory := CalculateIntermediateRecentHistory(newBlock.Header, s.RecentHistory)

	// ρ† ≺ (ED , ρ)
	intermediateCoreAssignments := disputing.CalculateIntermediateCoreAssignmentsFromExtrinsics(newBlock.Extrinsic.ED, s.CoreAssignments)

	// ψ′ ≺ (ED, ψ)
	newJudgements, err := disputing.ValidateDisputesExtrinsicAndProduceJudgements(prevTimeSlot, newBlock.Extrinsic.ED, s.ValidatorState, s.PastJudgements)
	if err != nil {
		return err
	}

	if err := ValidatePreimages(newBlock.Extrinsic.EP, s.Services); err != nil {
		return err
	}

	// TODO: verify header offenders marker.

	// Update SAFROLE state.
	safroleInput, err := NewSafroleInputFromBlock(newBlock)
	if err != nil {
		return err
	}
	newEntropyPool, newValidatorState, safroleOutput, err := UpdateSafroleState(
		safroleInput,
		prevTimeSlot,
		s.EntropyPool,
		s.ValidatorState,
		newJudgements.OffendingValidators)
	if err != nil {
		return err
	}

	err = VerifyBlockHeaderSafrole(newValidatorState, safroleOutput, newBlock)
	if err != nil {
		return fmt.Errorf("failed to verify block header: %w", err)
	}

	// ρ‡ ≺ (EA, ρ†) (eq. 4.13 v0.7.0) and R* ≺ (EA, ρ†) (eq 4.15 v0.7.0)
	intermediateCoreAssignments, availableWorkReports, err := assuring.CalculateIntermediateCoreAssignmentsAndAvailableWorkReports(newBlock.Extrinsic.EA, s.ValidatorState.CurrentValidators, intermediateCoreAssignments, newBlock.Header)
	if err != nil {
		return err
	}

	reporters, err := guaranteeing.ValidateGuaranteExtrinsicAndReturnReporters(newBlock.Extrinsic.EG, s, chain, newTimeSlot, intermediateRecentHistory, newBlock.Header, intermediateCoreAssignments)
	if err != nil {
		return err
	}
	// ρ′ ≺ (EG, ρ‡, κ, τ ′)
	newCoreAssignments := guaranteeing.CalculatePosteriorCoreAssignments(newBlock.Extrinsic.EG, intermediateCoreAssignments, newTimeSlot)

	newAccumulationQueue,
		newAccumulationHistory,
		postAccumulationServiceState,
		newPrivilegedServices,
		newQueuedValidators,
		newPendingCoreAuthorizations,
		accumulationOutputLog, accumulationStats, transferStats := CalculateWorkReportsAndAccumulate(
		&newBlock.Header,
		s,
		newTimeSlot,
		availableWorkReports,
	)
	finalServicesState, err := CalculateNewServiceStateWithPreimages(newBlock.Extrinsic.EP, postAccumulationServiceState, newBlock.Header.TimeSlotIndex)
	if err != nil {
		return err
	}

	// TODO: pass correct available reports.
	newValidatorStatistics := CalculateNewActivityStatistics(newBlock, prevTimeSlot, s.ActivityStatistics, reporters, s.ValidatorState.CurrentValidators,
		[]block.WorkReport{}, accumulationStats, transferStats)

	newRecentHistory, err := CalculateNewRecentHistory(newBlock.Header, newBlock.Extrinsic.EG, intermediateRecentHistory, accumulationOutputLog)
	if err != nil {
		return err
	}

	newCoreAuthorizations := CalculateNewCoreAuthorizations(newBlock.Header, newBlock.Extrinsic.EG, newPendingCoreAuthorizations, s.CoreAuthorizersPool)

	// Update the state with new state values.
	s.TimeslotIndex = newTimeSlot
	s.EntropyPool = newEntropyPool
	s.ValidatorState = newValidatorState
	s.ValidatorState.QueuedValidators = newQueuedValidators
	s.ActivityStatistics = newValidatorStatistics
	s.RecentHistory = newRecentHistory
	s.CoreAssignments = newCoreAssignments
	s.PastJudgements = newJudgements
	s.CoreAuthorizersPool = newCoreAuthorizations
	s.Services = finalServicesState
	s.PrivilegedServices = newPrivilegedServices
	s.AccumulationQueue = newAccumulationQueue
	s.AccumulationHistory = newAccumulationHistory
	s.AccumulationOutputLog = state.AccumulationOutputLog(accumulationOutputLog)

	return nil
}

// Intermediate State Calculation Functions

// preimageHasBeenSolicited checks if a preimage has been solicited but not yet provided
// Y(d, s, h, l) ⇔ h ∉ d[s]p ∧ d[s]l[(h, l)] = [] (eq. 12.41 v0.7.0)
func preimageHasBeenSolicited(serviceState service.ServiceState, serviceIndex block.ServiceId, preimageHash crypto.Hash, preimageLength service.PreimageLength) bool {
	account, ok := serviceState[serviceIndex]
	if !ok {
		return false
	}
	_, preimageLookupExists := account.PreimageLookup[preimageHash]

	k, err := statekey.NewPreimageMeta(serviceIndex, preimageHash, uint32(preimageLength))
	if err != nil {
		return false
	}
	meta, metaExists := account.GetPreimageMeta(k)

	return !preimageLookupExists && (metaExists && len(meta) == 0)
}

// EP = [i ∈ EP || i] (eq. 12.39)
func isPreimagesSortedUnique(preimages block.PreimageExtrinsic) bool {
	if len(preimages) <= 1 {
		return true
	}

	for i := 1; i < len(preimages); i++ {
		prev := preimages[i-1]
		current := preimages[i]

		if current.ServiceIndex < prev.ServiceIndex {
			return false
		}

		if current.ServiceIndex == prev.ServiceIndex &&
			bytes.Compare(current.Data, prev.Data) <= 0 {
			return false
		}
	}
	return true
}

// ValidatePreimages implements equations 12.39 and 12.40 v0.7.0
// checks that the preimages are ordered, unique and solicited by a service
func ValidatePreimages(preimages block.PreimageExtrinsic, serviceState service.ServiceState) error {
	if !isPreimagesSortedUnique(preimages) {
		return errors.New("preimages not sorted unique")
	}

	for _, preimage := range preimages {
		serviceId := block.ServiceId(preimage.ServiceIndex)
		preimageHash := crypto.HashData(preimage.Data)
		preimageLength := service.PreimageLength(len(preimage.Data))

		// ∀(s, p) ∈ E_P∶ R(δ, s, H(p), |p|) (eq. 12.40 v0.7.0)
		if !preimageHasBeenSolicited(serviceState, serviceId, preimageHash, preimageLength) {
			return errors.New("preimage unneeded")
		}
	}

	return nil
}

// CalculateNewServiceStateWithPreimages implements Equations 12.42 and 12.43 v0.7.0
// This function calculates the final service state δ′ based on:
// - The current service state δ (serviceState)
// - The preimage extrinsic EP (preimages)
// - The new timeslot τ′ (newTimeslot)
//
// For each preimage in EP:
//  1. It adds the preimage p to the PreimageLookup of service s, keyed by its hash H(d)
//  2. It adds a new entry to the PreimageMeta of service s, keyed by the hash H(d) and
//     length |d|, with the value being the new timeslot τ′
//
// The function returns a new ServiceState without modifying the input state.
func CalculateNewServiceStateWithPreimages(
	preimages block.PreimageExtrinsic,
	postAccumulationServiceState service.ServiceState,
	newTimeslot jamtime.Timeslot,
) (service.ServiceState, error) {

	newServiceState := postAccumulationServiceState.Clone()

	for _, preimage := range preimages {
		serviceId := block.ServiceId(preimage.ServiceIndex)
		preimageHash := crypto.HashData(preimage.Data)
		preimageLength := service.PreimageLength(len(preimage.Data))

		// let p = { (s, d) | (s, d) ∈ EP, Y(δ‡, s, H(d), |d|) } (eq. 12.42 v0.7.0)
		if !preimageHasBeenSolicited(postAccumulationServiceState, serviceId, preimageHash, preimageLength) {
			continue
		}

		// Eq. 12.43 v0.7.0
		//							⎧ δ′[s]p[H(d)] = d
		// δ′ = δ‡ ex. ∀(s, d) ∈ p∶ ⎨
		// 							⎩ δ′[s]l[H(d), |d|] = [τ′]
		account, ok := postAccumulationServiceState[serviceId]
		if !ok {
			continue
		}
		// If checks pass, add the new preimage
		if account.PreimageLookup == nil {
			account.PreimageLookup = make(map[crypto.Hash][]byte)
		}
		account.PreimageLookup[preimageHash] = preimage.Data

		k, err := statekey.NewPreimageMeta(serviceId, preimageHash, uint32(preimageLength))
		if err != nil {
			return nil, err
		}

		err = account.InsertPreimageMeta(k, uint64(preimageLength), service.PreimageHistoricalTimeslots{newTimeslot})
		if err != nil {
			return nil, err
		}

		newServiceState[serviceId] = account
	}

	return newServiceState, nil
}

// Final State Calculation Functions

// CalculateNewTimeState Equation 16: τ′ ≺ H
func CalculateNewTimeState(header block.Header) jamtime.Timeslot {
	return header.TimeSlotIndex
}

// CalculateIntermediateRecentHistory implements equations:
// 4.6: β†_H ≺ (H, β_H)
// Equation 7.5: β†[SβS − 1]s = Hr
// Computes the intermediate recent history.
func CalculateIntermediateRecentHistory(header block.Header, priorRecentHistory state.RecentHistory) state.RecentHistory {

	intermediateRecentHistory := priorRecentHistory.Clone()

	// Equation 7.5: β†[SβS − 1]s = Hr
	if len(intermediateRecentHistory.BlockHistory) > 0 {
		intermediateRecentHistory.BlockHistory[len(intermediateRecentHistory.BlockHistory)-1].StateRoot = header.PriorStateRoot
	}

	return intermediateRecentHistory
}

// CalculateNewRecentHistory implements equations:
// 4.17: β′_H ≺ (H, EG, β†_H , θ′)
// 7.5 - 7.8
// Computes the final recent history.
func CalculateNewRecentHistory(header block.Header, guarantees block.GuaranteesExtrinsic, intermediateRecentHistory state.RecentHistory, serviceHashPairs ServiceHashPairs) (state.RecentHistory, error) {

	// Gather all the inputs we need.

	// Header hash, equation 7.8: H(H)
	headerBytes, err := jam.Marshal(header)
	if err != nil {
		return state.RecentHistory{}, err
	}
	headerHash := crypto.HashData(headerBytes)

	// Equation 7.6: let s = [E_4(s) ⌢ E(h) | (s, h) <− θ′]
	// And Equation 7.7: M_B(s, H_K)
	accumulationRoot, err := computeAccumulationRoot(serviceHashPairs)
	if err != nil {
		return state.RecentHistory{}, err
	}

	// Equation 7.8: p = {((g_w)_s)_h ↦ ((g_w)_s)_e | g ∈ E_G}
	workPackageMapping := buildWorkPackageMapping(guarantees.Guarantees)

	// Update β to produce β'.
	newRecentHistory, err := UpdateRecentHistory(headerHash, accumulationRoot, workPackageMapping, intermediateRecentHistory)
	if err != nil {
		return state.RecentHistory{}, err
	}

	return newRecentHistory, nil
}

// UpdateRecentHistory updates β, i.e β′_B and β′_H.
// It implements equations:
// Equation 7.7: β′_B ≡ A(β_B , M_B (s, HK ), HK)
// Equation 7.8: β′_H ≡ β†_H ++ (p, h: H(H), b: M_R(β′_B), s:H0)
// We separate out this logic for ease of testing aganist the recent history
// test vectors.
func UpdateRecentHistory(
	headerHash crypto.Hash,
	accumulationRoot crypto.Hash,
	workPackageMapping map[crypto.Hash]crypto.Hash,
	intermediateRecentHistory state.RecentHistory) (state.RecentHistory, error) {

	newRecentHistory := intermediateRecentHistory.Clone()

	mountainRange := mountain_ranges.New()

	// Equation 7.7: β′_B ≡ A(β_B , M_B (s, HK ), HK)
	newRecentHistory.AccumulationOutputLog = mountainRange.Append(newRecentHistory.AccumulationOutputLog, accumulationRoot, crypto.KeccakData)

	newBlockState := state.BlockState{
		HeaderHash: headerHash,                                                                         // h: H(H)
		StateRoot:  crypto.Hash{},                                                                      // s: H_0
		BeefyRoot:  mountainRange.SuperPeak(newRecentHistory.AccumulationOutputLog, crypto.KeccakData), // b: M_R(β′_B)
		Reported:   workPackageMapping,                                                                 // p
	}

	// Equation 7.8: β′_H ≡ β†_H ++ (p, h: H(H), b: M_R(β′_B), s:H0)
	// First append new block state
	newRecentHistory.BlockHistory = append(newRecentHistory.BlockHistory, newBlockState)

	// Then keep only last H blocks
	if len(newRecentHistory.BlockHistory) > state.MaxRecentBlocks {
		newRecentHistory.BlockHistory = newRecentHistory.BlockHistory[len(newRecentHistory.BlockHistory)-state.MaxRecentBlocks:]
	}

	return newRecentHistory, nil
}

// This should create a Merkle tree from the accumulations and return the root.
// Implements:
// Equation 7.6: let s = [E_4(s) ⌢ E(h) | (s, h) <− θ′]
// Equation 7.7: M_B(s, H_K)
func computeAccumulationRoot(pairs ServiceHashPairs) (crypto.Hash, error) {
	if len(pairs) == 0 {
		return crypto.Hash{}, nil
	}

	// Sort pairs to ensure deterministic ordering
	sort.Slice(pairs, func(i, j int) bool {
		return pairs[i].ServiceId < pairs[j].ServiceId
	})

	// Create sequence of [s ^^ E_4(s) ⌢ E(h)] for each (s,h) pair
	items := make([][]byte, len(pairs))
	for i, pair := range pairs {
		// Create concatenated item
		item := make([]byte, 0)

		s, err := jam.Marshal(pair.ServiceId)
		if err != nil {
			return crypto.Hash{}, err
		}

		// Append service ID encoding
		item = append(item, s...)

		h, err := jam.Marshal(pair.Hash)
		if err != nil {
			return crypto.Hash{}, err
		}
		// Append hash encoding
		item = append(item, h...)

		items[i] = item
	}

	// Compute MB([s ^^ E_4(s) ⌢ E(h)], HK) using well-balanced Merkle tree
	return binary_tree.ComputeWellBalancedRoot(items, crypto.KeccakData), nil
}

// buildWorkPackageMapping creates the work package mapping p from equation 7.8:
// p = {((gw)s)h ↦ ((gw)s)e | g ∈ EG}
func buildWorkPackageMapping(guarantees []block.Guarantee) map[crypto.Hash]crypto.Hash {
	workPackages := make(map[crypto.Hash]crypto.Hash)
	for _, g := range guarantees {
		workPackages[g.WorkReport.AvailabilitySpecification.WorkPackageHash] =
			g.WorkReport.AvailabilitySpecification.SegmentRoot
	}
	return workPackages
}

// CalculateNewCoreAuthorizations implements equation 4.19: α' ≺ (H, EG, φ', α) . Graypaper 0.5.4
func CalculateNewCoreAuthorizations(header block.Header, guarantees block.GuaranteesExtrinsic, pendingAuthorizations state.PendingAuthorizersQueues, currentAuthorizations state.CoreAuthorizersPool) state.CoreAuthorizersPool {
	var newCoreAuthorizations state.CoreAuthorizersPool

	// For each core
	for c := uint16(0); c < common.TotalNumberOfCores; c++ {
		// Start with the existing authorizations for this core
		newAuths := make([]crypto.Hash, len(currentAuthorizations[c]))
		copy(newAuths, currentAuthorizations[c])

		// Track whether a guarantee's authorizer removal has occurred
		guaranteeAuthorizerRemoved := false

		// F(c) - Remove authorizer if it was used in a guarantee for this core. 8.3 Graypaper 0.6.2
		for _, guarantee := range guarantees.Guarantees {
			if guarantee.WorkReport.CoreIndex == c {
				// Remove the used authorizer from the list
				newAuths = removeAuthorizer(newAuths, guarantee.WorkReport.AuthorizerHash)
				guaranteeAuthorizerRemoved = true
			}
		}

		// If no guarantee was found for this core, then left-shift the authorizers (remove the first element)
		if !guaranteeAuthorizerRemoved && len(newAuths) > 0 {
			newAuths = newAuths[1:]
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
//
//lint:ignore U1000
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

// CalculateWorkReportsAndAccumulate implements equations. We pass W instead of W* because we also need WQ for
// updating the state queue.
// (ω′, ξ′, δ‡, χ′, ι′, ϕ′, θ′, S, X) ≺ (R, ω, ξ, δ, χ, ι, ϕ, τ, τ′) (eq. 4.16)
func CalculateWorkReportsAndAccumulate(header *block.Header, currentState *state.State, newTimeslot jamtime.Timeslot, workReports []block.WorkReport) (
	newAccumulationQueue state.AccumulationQueue,
	newAccumulationHistory state.AccumulationHistory,
	postAccumulationServiceState service.ServiceState,
	newPrivilegedServices service.PrivilegedServices,
	newValidatorKeys safrole.ValidatorsData,
	newPendingAuthorizersQueues state.PendingAuthorizersQueues,
	accumulationOutputLog ServiceHashPairs,
	accumulationStats AccumulationStats,
	transfersStats DeferredTransfersStats,
) {
	// R! ≡ [w | w <− R, |(w_c)p| = 0 ∧ wl = {}] (eq. 12.4 v0.7.0)
	var immediatelyAccWorkReports []block.WorkReport
	var workReportWithDeps []state.WorkReportWithUnAccumulatedDependencies
	for _, workReport := range workReports {
		if len(workReport.RefinementContext.PrerequisiteWorkPackage) == 0 && len(workReport.SegmentRootLookup) == 0 {
			immediatelyAccWorkReports = append(immediatelyAccWorkReports, workReport)
		} else if len(workReport.RefinementContext.PrerequisiteWorkPackage) > 0 || len(workReport.SegmentRootLookup) != 0 {
			// |(w_x)p| > 0 ∨ wl ≠ {} (part of eq. 12.5 v0.7.0)
			workReportWithDeps = append(workReportWithDeps, getWorkReportDependencies(workReport))
		}
	}

	// RQ ≡ E([D(w) | w <− R, |(w_c)p| > 0 ∨ wl ≠ {}], {ξ) (eq. 12.5 v0.7.0)
	var queuedWorkReports = updateQueue(workReportWithDeps, flattenAccumulationHistory(currentState.AccumulationHistory))

	// let m = Ht mod E (eq. 12.10 v0.7.0)
	timeslotPerEpoch := header.TimeSlotIndex % jamtime.TimeslotsPerEpoch

	// q = E(⋃(ωm...) ⌢ ⋃(ω...m) ⌢ RQ, P(R!)) (eq. 12.12 v0.7.0)
	workReportsFromQueueDeps := updateQueue(
		slices.Concat(
			slices.Concat(currentState.AccumulationQueue[timeslotPerEpoch:]...), // ⋃(ωm...)
			slices.Concat(currentState.AccumulationQueue[:timeslotPerEpoch]...), // ⋃(ω...m)
			queuedWorkReports, // RQ
		),
		getWorkPackageHashes(immediatelyAccWorkReports), // P(R!)
	)
	// R* ≡ R! ⌢ Q(q) (eq. 12.11 v0.7.0)
	var accumulatableWorkReports = slices.Concat(immediatelyAccWorkReports, accumulationPriority(workReportsFromQueueDeps))

	privSvcGas := uint64(0)
	for _, gas := range currentState.PrivilegedServices.AmountOfGasPerServiceId {
		privSvcGas += gas
	}
	// let g = max(GT, GA ⋅ C + [∑x∈V(χ_Z)](x)) (eq. 12.22 v0.7.0)
	gasLimit := max(service.TotalGasAccumulation, common.MaxAllocatedGasAccumulation*uint64(common.TotalNumberOfCores)+privSvcGas)

	accumulator := NewAccumulator(currentState, header, newTimeslot)
	// e = (d: δ, i: ι, q: ϕ, m: χ_M, a: χ_A, v: χ_V, z: χ_Z) (eq. 12.23 v0.7.0)
	// (n, e′, t, θ′, u) ≡ ∆+(g, R*, e, χ_Z) (eq. 12.24 v0.7.0)
	accumulatedCount, newAccumulationState, transfers, accumulationOutputLog, gasPairs := accumulator.
		SequentialDelta(gasLimit, accumulatableWorkReports, state.AccumulationState{
			ServiceState:             currentState.Services,
			ValidatorKeys:            currentState.ValidatorState.QueuedValidators,
			PendingAuthorizersQueues: currentState.PendingAuthorizersQueues,
			ManagerServiceId:         currentState.PrivilegedServices.ManagerServiceId,
			AssignedServiceIds:       currentState.PrivilegedServices.AssignedServiceIds,
			DesignateServiceId:       currentState.PrivilegedServices.DesignateServiceId,
			AmountOfGasPerServiceId:  currentState.PrivilegedServices.AmountOfGasPerServiceId,
		}, currentState.PrivilegedServices.AmountOfGasPerServiceId)

	// (χ′, δ†, ι′, φ′) ≡ o (eq. 12.23 v0.7.0)
	// (d: δ†, i: ι′, q: ϕ′, m: χ′_M, a: χ′_A, v: χ′_V , z: χ′_Z ) ≡ e′ (eq. 12.25 v0.7.0)
	intermediateServiceState := newAccumulationState.ServiceState
	newPrivilegedServices = service.PrivilegedServices{
		ManagerServiceId:        newAccumulationState.ManagerServiceId,
		AssignedServiceIds:      newAccumulationState.AssignedServiceIds,
		DesignateServiceId:      newAccumulationState.DesignateServiceId,
		AmountOfGasPerServiceId: newAccumulationState.AmountOfGasPerServiceId,
	}
	newValidatorKeys = newAccumulationState.ValidatorKeys
	newPendingAuthorizersQueues = newAccumulationState.PendingAuthorizersQueues

	// Compute accumulation statistics

	// N(s) ≡ [r | w <− R*...n, r <− w_r, r_s = s] (eq. 12.28 v0.7.0)
	accumulateCountBySvc := map[block.ServiceId]uint32{}
	for _, workReport := range accumulatableWorkReports[:accumulatedCount] {
		for _, result := range workReport.WorkDigests {
			accumulateCountBySvc[result.ServiceId]++
		}
	}

	// S ≡ {(s ↦ ([∑(s,u)∈u] (u), |N(s)|)) | N(s) ≠ []} (eq. 12.27 v0.7.0)
	accumulationStats = AccumulationStats{}
	for _, gp := range gasPairs {
		totalGas := accumulationStats[gp.ServiceId].AccumulateGasUsed
		totalGas += gp.Gas

		accumulateCount, ok := accumulateCountBySvc[gp.ServiceId]
		if ok {
			accumulationStats[gp.ServiceId] = AccumulationStatEntry{
				AccumulateGasUsed: totalGas,
				AccumulateCount:   accumulateCount,
			}
		}
	}

	// x  = {(s ↦ ΨT(δ†, τ′, s, X(s))) | (s ↦ a) ∈ δ†} (eq. 12.30 v0.7.0)
	// δ‡ ≡ {(s ↦ a′) | (s ↦ (a, u)) ∈ x} (12.31 v0.7.0)
	postAccumulationServiceState = make(service.ServiceState)

	// X ≡ {(d ↦(|X(d)|, u))| X(d) ≠ [], ∃a ∶ x[d] = (a, u)} (eq. 12.34 v0.7.0)
	transfersStats = DeferredTransfersStats{}

	for serviceId := range intermediateServiceState {
		// X(d)
		receiverTransfers := transfersForReceiver(transfers, serviceId)

		newService, gasUsed := accumulator.InvokePVMOnTransfer(
			intermediateServiceState,
			newTimeslot,
			serviceId,
			receiverTransfers,
		)

		// Eq. 12.32 v0.7.0
		//      ⎧ a except a′_a = τ′ if s ∈ K(S)
		// a′ = ⎨
		//      ⎩ a otherwise
		if _, ok := accumulationStats[serviceId]; !ok {
			newService.MostRecentAccumulationTimeslot = newTimeslot
		}

		postAccumulationServiceState[serviceId] = newService

		// X(d) ≠ []
		if len(receiverTransfers) > 0 {
			transfersStats[serviceId] = DeferredTransfersStatEntry{
				OnTransfersCount:   uint32(len(receiverTransfers)),
				OnTransfersGasUsed: gasUsed,
			}
		}
	}

	// ξ′E−1 = P(R*...n) (eq. 12.35 v0.7.0)
	// ∀i ∈ NE−1 ∶ ξ′i ≡ ξi+1 (eq. 12.36 v0.7.0)
	newAccumulationHistory = state.AccumulationHistory(append(
		currentState.AccumulationHistory[1:],
		getWorkPackageHashes(accumulatableWorkReports[:accumulatedCount]),
	))

	// ξ′E−1
	lastAccumulation := newAccumulationHistory[jamtime.TimeslotsPerEpoch-1]

	// Eq. 12.37 v0.7.0
	//					  ⎧ E(RQ, ξ′E−1) 		if i = 0
	// ∀i ∈ NE ∶ ω′↺m−i ≡ ⎨ [] 					if 1 ≤ i < τ′ − τ
	// 					  ⎩ E(ω↺m−i, ξ′E−1) 	if i ≥ τ′ − τ
	for i := range jamtime.TimeslotsPerEpoch {
		indexPerEpoch := mod(int(timeslotPerEpoch)-i, jamtime.TimeslotsPerEpoch)
		if i == 0 {
			newAccumulationQueue[indexPerEpoch] = updateQueue(queuedWorkReports, lastAccumulation)
		} else if 1 <= i && jamtime.Timeslot(i) < newTimeslot-currentState.TimeslotIndex {
			newAccumulationQueue[indexPerEpoch] = nil
		} else if jamtime.Timeslot(i) >= newTimeslot-currentState.TimeslotIndex {
			newAccumulationQueue[indexPerEpoch] = updateQueue(currentState.AccumulationQueue[indexPerEpoch], lastAccumulation)
		}
	}

	return
}

// accumulationPriority Q(r ⟦(R, {H})⟧) → ⟦R⟧ (eq. 12.8 v0.7.0)
func accumulationPriority(workReportAndDeps []state.WorkReportWithUnAccumulatedDependencies) []block.WorkReport {
	var workReports []block.WorkReport
	for _, wd := range workReportAndDeps {
		if len(wd.Dependencies) == 0 {
			workReports = append(workReports, wd.WorkReport)
		}
	}

	if len(workReports) == 0 {
		return []block.WorkReport{}
	}

	return append(workReports, accumulationPriority(updateQueue(workReportAndDeps, getWorkPackageHashes(workReports)))...)
}

// getWorkReportDependencies D(w) ≡ (w, {(w_c)p} ∪ K(w_l)) (eq. 12.6 v0.7.0)
func getWorkReportDependencies(workReport block.WorkReport) state.WorkReportWithUnAccumulatedDependencies {
	deps := make(map[crypto.Hash]struct{})
	for _, prereqHash := range workReport.RefinementContext.PrerequisiteWorkPackage {
		deps[prereqHash] = struct{}{}
	}
	for key := range workReport.SegmentRootLookup {
		deps[key] = struct{}{}
	}
	return state.WorkReportWithUnAccumulatedDependencies{
		WorkReport:   workReport,
		Dependencies: deps,
	}
}

// flattenAccumulationHistory {ξ ≡ x∈ξ ⋃(x) (eq. 12.2 v0.7.0)
func flattenAccumulationHistory(accHistory state.AccumulationHistory) (hashes map[crypto.Hash]struct{}) {
	hashes = make(map[crypto.Hash]struct{})
	for _, epochHistory := range accHistory {
		maps.Copy(hashes, epochHistory)
	}
	return hashes
}

// updateQueue E(r ⟦(R, {H})⟧, x {H}) → ⟦(R, {H})⟧ (eq. 12.7 v0.7.0)
func updateQueue(workRepAndDep []state.WorkReportWithUnAccumulatedDependencies, hashSet map[crypto.Hash]struct{}) []state.WorkReportWithUnAccumulatedDependencies {
	var newWorkRepsAndDeps []state.WorkReportWithUnAccumulatedDependencies
	for _, wd := range workRepAndDep {
		if _, ok := hashSet[wd.WorkReport.AvailabilitySpecification.WorkPackageHash]; !ok {
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

// P(w {R}) → {H} (eq. 12.9 v0.7.0)
func getWorkPackageHashes(workReports []block.WorkReport) (hashes map[crypto.Hash]struct{}) {
	hashes = make(map[crypto.Hash]struct{})
	// {(ws)h S w ∈ w}
	for _, workReport := range workReports {
		hashes[workReport.AvailabilitySpecification.WorkPackageHash] = struct{}{}
	}
	return hashes
}

// transfersForReceiver X(d NS) → ⟦X⟧ (eq. 12.29 v0.7.0)
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

// CalculateNewActivityStatistics updates activity statistics.
// It implements equation 4.20:
// π′ ≺ (EG, EP , EA, ET , τ, κ′, π, H, I, X)
// And the entire section 13.
// TODO complete service and core stats. For now we only support service stats
// for preimages, and no core stats yet.
func CalculateNewActivityStatistics(
	blk block.Block,
	prevTimeslot jamtime.Timeslot,
	activityStatistics validator.ActivityStatisticsState,
	reporters crypto.ED25519PublicKeySet,
	currValidators safrole.ValidatorsData,
	availableWorkReports []block.WorkReport,
	accumulationStats AccumulationStats,
	transferStats DeferredTransfersStats,
) validator.ActivityStatisticsState {
	current, last := CalculateNewValidatorStatistics(blk, prevTimeslot, activityStatistics.ValidatorsCurrent, activityStatistics.ValidatorsLast, reporters, currValidators)

	return validator.ActivityStatisticsState{
		ValidatorsCurrent: current,
		ValidatorsLast:    last,
		Cores:             CalculateNewCoreStatistics(blk, activityStatistics.Cores, availableWorkReports),
		Services:          CalculateNewServiceStatistics(blk, accumulationStats, transferStats),
	}
}

// CalculateNewValidatorStatistics updates validator statistics.
// It implements equations 13.3 - 13.5.
func CalculateNewValidatorStatistics(
	blk block.Block,
	prevTimeslot jamtime.Timeslot,
	validatorStatsCurrent, validatorStatsLast [common.NumberOfValidators]validator.ValidatorStatistics,
	reporters crypto.ED25519PublicKeySet,
	currValidators safrole.ValidatorsData,
) ([common.NumberOfValidators]validator.ValidatorStatistics, [common.NumberOfValidators]validator.ValidatorStatistics) { // (current, last)
	// Implements equations 13.3 - 13.4:
	// let e = ⌊τ/E⌋, e′ = ⌊τ′/E⌋
	// (a, π′₁) ≡ { (π₀, π₁) if e′ = e
	//              ([{0,...,[0,...]},...], π₀) otherwise
	if prevTimeslot.ToEpoch() != blk.Header.TimeSlotIndex.ToEpoch() {
		// Rotate statistics - completed stats become history, start fresh present stats
		validatorStatsLast = validatorStatsCurrent                                         // Move current to history
		validatorStatsCurrent = [common.NumberOfValidators]validator.ValidatorStatistics{} // Reset current
	}

	// Implements equation 13.5: ∀v ∈ NV
	for v := uint16(0); v < uint16(len(validatorStatsCurrent)); v++ {
		// π′₀[v]b ≡ a[v]b + (v = Hi)
		if v == blk.Header.BlockAuthorIndex {
			validatorStatsCurrent[v].NumOfBlocks++

			// π′₀[v]t ≡ a[v]t + {|ET| if v = Hi
			//                     0 otherwise
			validatorStatsCurrent[v].NumOfTickets += uint32(len(blk.Extrinsic.ET.TicketProofs))

			// π′₀[v]p ≡ a[v]p + {|EP| if v = Hi
			//                     0 otherwise
			validatorStatsCurrent[v].NumOfPreimages += uint32(len(blk.Extrinsic.EP))

			// π′₀[v]d ≡ a[v]d + {Σd∈EP|d| if v = Hi
			//                     0 otherwise
			for _, preimage := range blk.Extrinsic.EP {
				validatorStatsCurrent[v].NumOfBytesAllPreimages += uint32(len(preimage.Data))
			}
		}

		// π′₀[v]g ≡ a[v]g + (κ′v ∈ R)
		// Where R is the set of reporter keys defined in 11.26 0.6.5
		for reporter := range reporters {
			if !currValidators[v].IsEmpty() && slices.Equal(currValidators[v].Ed25519, reporter[:]) {
				validatorStatsCurrent[v].NumOfGuaranteedReports++
			}
		}

		// π′₀[v]a ≡ a[v]a + (∃a ∈ EA : av = v)
		for _, assurance := range blk.Extrinsic.EA {
			if assurance.ValidatorIndex == v {
				validatorStatsCurrent[v].NumOfAvailabilityAssurances++
			}
		}
	}

	return validatorStatsCurrent, validatorStatsLast
}

// CalculateNewCoreStatistics updates core statistics.
// It implements equations 13.8 - 13.10.
func CalculateNewCoreStatistics(
	blk block.Block,
	coreStats [common.TotalNumberOfCores]validator.CoreStatistics,
	availableReports []block.WorkReport, // W
) [common.TotalNumberOfCores]validator.CoreStatistics {
	newCoreStats := [common.TotalNumberOfCores]validator.CoreStatistics{}

	// Equation 13.9
	// ∑ r ∈wr,w ∈w, wc=c (ri, rx, rz , re, ru, b: (ws)l)
	for _, guarantee := range blk.Extrinsic.EG.Guarantees {
		workReport := guarantee.WorkReport
		coreIndex := workReport.CoreIndex
		for _, workResult := range workReport.WorkDigests {

			newCoreStats[coreIndex].Imports += workResult.SegmentsImportedCount
			newCoreStats[coreIndex].Exports += workResult.SegmentsExportedCount
			newCoreStats[coreIndex].ExtrinsicCount += workResult.ExtrinsicCount
			newCoreStats[coreIndex].ExtrinsicSize += workResult.ExtrinsicSize
			newCoreStats[coreIndex].GasUsed += workResult.GasUsed
			// TODO this might be out of the loop, but the equation looks like it's done for each result.
			newCoreStats[coreIndex].BundleSize += workReport.AvailabilitySpecification.AuditableWorkBundleLength

		}

	}

	// Equation 13.10
	// ∑ w ∈W, wc=c (ws)_l + W_G⌈(ws)_n65/64⌉
	// 65/64 likely adds overhead for proofs which require one segment for every 64 segments.
	for _, workReport := range availableReports {
		coreIndex := workReport.CoreIndex

		l := workReport.AvailabilitySpecification.AuditableWorkBundleLength
		n := workReport.AvailabilitySpecification.SegmentCount
		var daLoad uint32 = l + (common.SizeOfSegment * uint32(math.Ceil(float64(n)*65/64)))

		newCoreStats[coreIndex].DALoad += daLoad
	}

	// Equation 13.8
	// ∑ a ∈EA a_f[c]
	for _, assurance := range blk.Extrinsic.EA {
		for _, coreIndex := range assurance.SetCoreIndexes() {
			newCoreStats[coreIndex].Popularity++
		}
	}

	return newCoreStats
}

// CalculateNewServiceStatistics updates service statistics.
// It implements equation 13.11 - 13.15.
// TODO complete service stats, for now this only supports preimage stats.
func CalculateNewServiceStatistics(
	blk block.Block,
	accumulationStats AccumulationStats,
	transferStats DeferredTransfersStats,
) validator.ServiceStatistics {
	newServiceStats := validator.ServiceStatistics{}

	// Equation 13.11
	for _, preimage := range blk.Extrinsic.EP {
		serviceID := block.ServiceId(preimage.ServiceIndex)
		record := newServiceStats[serviceID]

		// p: ∑ (s,p) ∈EP (1, |p|)
		record.ProvidedCount++
		record.ProvidedSize += uint32(len(preimage.Data))

		newServiceStats[serviceID] = record
	}

	// Equation 13.15
	// ∑ r ∈wr,w ∈w, wc=c (ri, rx, rz , re, ru, b: (ws)l)
	for _, guarantee := range blk.Extrinsic.EG.Guarantees {
		workReport := guarantee.WorkReport
		for _, workResult := range workReport.WorkDigests {
			serviceID := block.ServiceId(workResult.ServiceId)
			record := newServiceStats[serviceID]

			record.Imports += uint32(workResult.SegmentsImportedCount)
			record.Exports += uint32(workResult.SegmentsExportedCount)
			record.ExtrinsicCount += uint32(workResult.ExtrinsicCount)
			record.ExtrinsicSize += uint32(workResult.ExtrinsicSize)
			record.RefinementCount += 1
			record.RefinementGasUsed += workResult.GasUsed

			newServiceStats[serviceID] = record
		}
	}

	// Equation 13.11
	// U(I[s], (0, 0))
	for serviceID, stat := range accumulationStats {
		record := newServiceStats[serviceID]

		record.AccumulateCount += stat.AccumulateCount
		record.AccumulateGasUsed += stat.AccumulateGasUsed

		newServiceStats[serviceID] = record
	}

	// Equation 13.11
	// U(X[s], (0, 0))
	for serviceID, stat := range transferStats {
		record := newServiceStats[serviceID]

		record.OnTransfersCount += stat.OnTransfersCount
		record.OnTransfersGasUsed += stat.OnTransfersGasUsed

		newServiceStats[serviceID] = record
	}

	return newServiceStats
}

// ServiceHashPairs B ≡ {(NS , H)} (eq. 12.15 v0.7.0)
type ServiceHashPairs []state.ServiceHashPair

// ServiceGasPairs U ≡ ⟦(NS , NG)⟧ (eq. 12.15 v0.7.0)
type ServiceGasPairs []ServiceGasPair

// AccumulationStats S ∈ ⟨NS → (NG, N)⟩ (eq. 12.26 v0.7.0)
type AccumulationStats map[block.ServiceId]AccumulationStatEntry

type AccumulationStatEntry struct {
	AccumulateGasUsed uint64
	AccumulateCount   uint32
}

// DeferredTransfersStats X ∈ ⟨NS → (N, NG)⟩ (eq. 12.33 v0.7.0)
type DeferredTransfersStats map[block.ServiceId]DeferredTransfersStatEntry

type DeferredTransfersStatEntry struct {
	OnTransfersCount   uint32
	OnTransfersGasUsed uint64
}

type ServiceGasPair struct {
	ServiceId block.ServiceId
	Gas       uint64
}

// SequentialDelta implements equation 12.16 v0.7.0 (∆+(NG, ⟦R⟧, S, ⟨NS → NG⟩) → (N, S, ⟦X⟧, B, U))
func (a *Accumulator) SequentialDelta(
	gasLimit uint64,
	workReports []block.WorkReport,
	ctx state.AccumulationState,
	alwaysAccumulate map[block.ServiceId]uint64,
) (
	uint32,
	state.AccumulationState,
	[]service.DeferredTransfer,
	ServiceHashPairs,
	ServiceGasPairs,
) {
	// If no work reports, return early
	if len(workReports) == 0 {
		return 0, ctx, nil, ServiceHashPairs{}, ServiceGasPairs{}
	}

	// Calculate i = max(N|w|+1) : ∑w∈w...i∑r∈wd(rg) ≤ g
	maxReports := 0
	totalGas := uint64(0)

	// Sum up gas requirements until we exceed limit
	for i, report := range workReports {
		reportGas := uint64(0)
		for _, result := range report.WorkDigests {
			reportGas += result.GasLimit
		}

		if totalGas+reportGas > gasLimit {
			break
		}

		totalGas += reportGas
		maxReports = i + 1
	}

	// If no reports can be processed, return early
	if maxReports == 0 {
		return 0, ctx, nil, ServiceHashPairs{}, ServiceGasPairs{}
	}

	// Process maxReports using ParallelDelta (∆*)
	newCtx, transfers, hashPairs, gasPairs := a.ParallelDelta(
		ctx,
		workReports[:maxReports],
		alwaysAccumulate,
	)

	// [∑(s,u) ∈ u∗] u
	var gasUsed uint64
	for _, pair := range gasPairs {
		gasUsed += pair.Gas
	}

	// If we have remaining reports and gas, process recursively (∆+)
	if maxReports < len(workReports) {
		remainingGas := gasLimit - gasUsed
		if remainingGas > 0 {
			moreItems, finalCtx, moreTransfers, moreHashPairs, moreGasPairs := a.SequentialDelta(
				remainingGas,
				workReports[maxReports:],
				newCtx,
				alwaysAccumulate,
			)

			return uint32(maxReports) + moreItems,
				finalCtx,
				append(transfers, moreTransfers...),
				append(hashPairs, moreHashPairs...),
				append(gasPairs, moreGasPairs...)
		}
	}

	return uint32(maxReports), newCtx, transfers, hashPairs, gasPairs
}

// ParallelDelta implements equation 12.17 v0.7.0 (∆*(S, ⟦R⟧, ⟨NS → NG⟩) → (S, ⟦X⟧, B, U))
func (a *Accumulator) ParallelDelta(
	initialAccState state.AccumulationState,
	workReports []block.WorkReport,
	alwaysAccumulate map[block.ServiceId]uint64, // D⟨NS → NG⟩
) (
	state.AccumulationState, // updated context
	[]service.DeferredTransfer, // all transfers
	ServiceHashPairs, // accumulation outputs
	ServiceGasPairs, // accumulation gas
) {
	// Get all unique service indices involved (s)
	// s = {rs | w ∈ w, r ∈ wr} ∪ K(f)
	serviceIndices := make(map[block.ServiceId]struct{})

	// From work reports
	for _, report := range workReports {
		for _, result := range report.WorkDigests {
			serviceIndices[result.ServiceId] = struct{}{}
		}
	}

	// From privileged gas assignments
	for svcId := range alwaysAccumulate {
		serviceIndices[svcId] = struct{}{}
	}

	var totalGasUsed uint64
	var allTransfers []service.DeferredTransfer
	// u = [(s, ∆1(o, w, f , s)u) | s <− s]
	accumHashPairs := make(ServiceHashPairs, 0)
	accumGasPairs := make(ServiceGasPairs, 0)
	newAccState := state.AccumulationState{
		ServiceState: initialAccState.ServiceState.Clone(),
	}

	// a*
	var intermediateAssignServiceId [common.TotalNumberOfCores]block.ServiceId
	// v*
	var intermediateDesignateServiceId block.ServiceId

	var allPreimageProvisions []polkavm.ProvidedPreimage

	var mu sync.Mutex
	var wg sync.WaitGroup

	for svcId := range serviceIndices {
		wg.Add(1)
		go func(serviceId block.ServiceId) {
			defer wg.Done()

			// Process single service using Delta1
			output := a.Delta1(initialAccState, workReports, alwaysAccumulate, serviceId)
			accState, deferredTransfers, resultHash, gasUsed, preimageProvisions := output.AccumulationState, output.DeferredTransfers, output.Result, output.GasUsed, output.ProvidedPreimages
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
				accumHashPairs = append(accumHashPairs, state.ServiceHashPair{
					ServiceId: serviceId,
					Hash:      *resultHash,
				})
			}
			accumGasPairs = append(accumGasPairs, ServiceGasPair{
				ServiceId: serviceId,
				Gas:       gasUsed,
			})

			allPreimageProvisions = append(allPreimageProvisions, preimageProvisions...)
			// Adds the newly created services after accumulation to the service state set
			// Removes the deleted services from the state
			//
			// n = ⋃[s∈s]({(∆1(o, w, f, s)e)d ∖ K(d ∖ {s})})
			// m = ⋃[s∈s](K(d) ∖ K((∆1(o, w, f, s)e)d))
			// (d ∪ n) ∖ m
			maps.Copy(newAccState.ServiceState, accState.ServiceState)
			for svc := range newAccState.ServiceState {
				if svc == serviceId {
					continue
				}

				_, ok := accState.ServiceState[svc]
				if !ok {
					delete(newAccState.ServiceState, svc)
				}
			}
		}(svcId)
	}

	wg.Add(1)
	go func(serviceId block.ServiceId) {
		defer wg.Done()

		// Process single service using Delta1
		output := a.Delta1(initialAccState, workReports, alwaysAccumulate, serviceId)
		mu.Lock()
		defer mu.Unlock()

		newAccState.ManagerServiceId = output.AccumulationState.ManagerServiceId
		intermediateAssignServiceId = output.AccumulationState.AssignedServiceIds
		intermediateDesignateServiceId = output.AccumulationState.DesignateServiceId
		newAccState.AmountOfGasPerServiceId = output.AccumulationState.AmountOfGasPerServiceId
	}(initialAccState.ManagerServiceId)

	// i′ = (∆1(o, w, f, v)e)i
	wg.Add(1)
	go func(serviceId block.ServiceId) {
		defer wg.Done()

		// Process single service using Delta1
		output := a.Delta1(initialAccState, workReports, alwaysAccumulate, serviceId)
		mu.Lock()
		defer mu.Unlock()

		newAccState.ValidatorKeys = output.AccumulationState.ValidatorKeys
	}(newAccState.DesignateServiceId)

	// ∀c ∈ NC ∶ q′c = ((∆1(o, w, f , a_c)e)q)c
	for core, assignServiceId := range newAccState.AssignedServiceIds {
		wg.Add(1)
		go func(serviceId block.ServiceId) {
			defer wg.Done()

			// Process single service using Delta1
			output := a.Delta1(initialAccState, workReports, alwaysAccumulate, serviceId)
			mu.Lock()
			newAccState.PendingAuthorizersQueues[core] = output.AccumulationState.PendingAuthorizersQueues[core]
			defer mu.Unlock()
		}(assignServiceId)
	}

	// Wait for manager, assign, designate and worker services
	wg.Wait()

	// d′ = P ((d ∪ n) ∖ m, [⋃s∈s] ∆1(o, w, f , s)p)
	newAccState.ServiceState = a.preimageIntegration(newAccState.ServiceState, allPreimageProvisions)

	// ∀c ∈ NC ∶ a′_c = ((∆1(o, w, f, a*_c )e)a)c
	for core, assignServiceId := range intermediateAssignServiceId {
		wg.Add(1)
		go func(serviceId block.ServiceId) {
			defer wg.Done()

			// Process single service using Delta1
			output := a.Delta1(initialAccState, workReports, alwaysAccumulate, serviceId)
			mu.Lock()
			newAccState.AssignedServiceIds[core] = output.AccumulationState.AssignedServiceIds[core]
			defer mu.Unlock()
		}(assignServiceId)
	}

	// v′ = (∆1(o, w, f , v*)e)v
	wg.Add(1)
	go func(serviceId block.ServiceId) {
		defer wg.Done()

		// Process single service using Delta1
		output := a.Delta1(initialAccState, workReports, alwaysAccumulate, serviceId)
		mu.Lock()
		defer mu.Unlock()
		newAccState.DesignateServiceId = output.AccumulationState.DesignateServiceId
	}(intermediateDesignateServiceId)

	// Wait for the intermediate assign and designate services id assign
	wg.Wait()

	// Sort accumulation pairs by service ID to ensure deterministic output
	sort.Slice(accumHashPairs, func(i, j int) bool {
		return accumHashPairs[i].ServiceId < accumHashPairs[j].ServiceId
	})

	return newAccState, allTransfers, accumHashPairs, accumGasPairs
}

// Delta1 implements equation 12.21 v0.7.0 ∆1(S, ⟦R⟧, ⟨NS → NG⟩, NS) → O
func (a *Accumulator) Delta1(
	accumulationState state.AccumulationState,
	workReports []block.WorkReport,
	alwaysAccumulate map[block.ServiceId]uint64, // D⟨NS → NG⟩
	serviceIndex block.ServiceId, // NS
) AccumulationOutput {
	// Calculate gas limit (g)
	gasLimit := uint64(0)
	if gas, exists := alwaysAccumulate[serviceIndex]; exists {
		gasLimit = gas
	}

	// Add gas from all relevant work items for this service
	for _, report := range workReports {
		for _, result := range report.WorkDigests {
			if result.ServiceId == serviceIndex {
				gasLimit += result.GasLimit
			}
		}
	}

	// Collect work item operands (p)
	var operands []state.AccumulationOperand
	for _, report := range workReports {
		for _, result := range report.WorkDigests {
			if result.ServiceId == serviceIndex {
				operand := state.AccumulationOperand{
					WorkPackageHash:   report.AvailabilitySpecification.WorkPackageHash,
					SegmentRoot:       report.AvailabilitySpecification.SegmentRoot,
					AuthorizationHash: report.AuthorizerHash,
					Trace:             report.AuthorizerTrace,
					PayloadHash:       result.PayloadHash,
					GasLimit:          result.GasLimit,
					OutputOrError:     result.Output,
				}
				operands = append(operands, operand)
			}
		}
	}

	// InvokePVM VM for accumulation (ΨA)
	return a.InvokePVM(accumulationState, a.newTimeslot, serviceIndex, gasLimit, operands)
}

// P(d ⟨NS → A⟩,p {(NS , B)}) → ⟨NS → A⟩ (eq. 12.18 v0.7.0)
func (a *Accumulator) preimageIntegration(services service.ServiceState, preimages []polkavm.ProvidedPreimage) service.ServiceState {
	servicesWithPreimages := services.Clone()

	// ∀(s, i) ∈ p, s ∈ K(d), d[s]l[H(i), |i|] = []∶
	for _, preimage := range preimages {
		preimageHash := crypto.HashData(preimage.Data)
		if srv, ok := services[preimage.ServiceId]; ok {
			k, err := statekey.NewPreimageMeta(preimage.ServiceId, preimageHash, uint32(len(preimage.Data)))
			if err != nil {
				panic("failed to create state key")
			}

			timeslots, exists := srv.GetPreimageMeta(k)

			if exists && len(timeslots) == 0 {
				// d′ where d′ = d except:
				// d′[s]l[H(i), |i|] = [τ′]
				// d′[s]p[H(i)] = i
				serviceWithPreimage := servicesWithPreimages[preimage.ServiceId]

				err = serviceWithPreimage.InsertPreimageMeta(k, uint64(len(preimage.Data)), service.PreimageHistoricalTimeslots{a.newTimeslot})
				if err != nil {
					panic("failed to insert preimage meta")
				}

				serviceWithPreimage.PreimageLookup[preimageHash] = preimage.Data
			}
		}
	}
	return servicesWithPreimages
}

func mod(a, b int) int {
	m := a % b
	if a < 0 && b < 0 {
		m -= b
	}
	if a < 0 && b > 0 {
		m += b
	}
	return m
}
