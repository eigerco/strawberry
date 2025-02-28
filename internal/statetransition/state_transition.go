package statetransition

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"
	"log"
	"maps"
	"slices"
	"sort"
	"sync"

	"github.com/eigerco/strawberry/internal/block"
	"github.com/eigerco/strawberry/internal/common"
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/crypto/bandersnatch"
	"github.com/eigerco/strawberry/internal/jamtime"
	"github.com/eigerco/strawberry/internal/merkle/binary_tree"
	"github.com/eigerco/strawberry/internal/merkle/mountain_ranges"
	"github.com/eigerco/strawberry/internal/polkavm"
	"github.com/eigerco/strawberry/internal/safrole"
	"github.com/eigerco/strawberry/internal/service"
	"github.com/eigerco/strawberry/internal/state"
	"github.com/eigerco/strawberry/internal/store"
	"github.com/eigerco/strawberry/internal/validator"
	"github.com/eigerco/strawberry/pkg/serialization/codec/jam"
)

// UpdateState updates the state
// TODO: all the calculations which are not dependent on intermediate / new state can be done in parallel
//
//	it might be worth making State immutable and make it so that UpdateState returns a new State with all the updated fields
func UpdateState(s *state.State, newBlock block.Block, chain *store.Chain) error {
	if newBlock.Header.TimeSlotIndex.IsInFuture() {
		return errors.New("invalid block, it is in the future")
	}

	newTimeState := CalculateNewTimeState(newBlock.Header)

	if err := ValidateExtrinsicGuarantees(newBlock.Header, s, newBlock.Extrinsic.EG, s.CoreAssignments, newTimeState, chain); err != nil {
		return fmt.Errorf("extrinsic guarantees validation failed, err: %w", err)
	}

	intermediateCoreAssignments := CalculateIntermediateCoreAssignmentsFromExtrinsics(newBlock.Extrinsic.ED, s.CoreAssignments)

	// Update SAFROLE state.
	safroleInput, err := NewSafroleInputFromBlock(newBlock)
	if err != nil {
		return err
	}
	newEntropyPool, newValidatorState, _, err := UpdateSafroleState(safroleInput, s.TimeslotIndex, s.EntropyPool, s.ValidatorState)
	if err != nil {
		return err
	}

	intermediateCoreAssignments, _, err = CalculateIntermediateCoreFromAssurances(newValidatorState.CurrentValidators, intermediateCoreAssignments, newBlock.Header, newBlock.Extrinsic.EA)
	if err != nil {
		return err
	}

	newCoreAssignments, reporters, err := CalculateNewCoreAssignments(newBlock.Extrinsic.EG, intermediateCoreAssignments, s.ValidatorState, newTimeState, newEntropyPool)
	if err != nil {
		return err
	}
	newValidatorStatistics := CalculateNewValidatorStatistics(newBlock, newTimeState, s.ValidatorStatistics, reporters, s.ValidatorState.CurrentValidators)

	workReports := GetAvailableWorkReports(newCoreAssignments)

	newAccumulationQueue,
		newAccumulationHistory,
		postAccumulationServiceState,
		newPrivilegedServices,
		newQueuedValidators,
		newPendingCoreAuthorizations,
		serviceHashPairs := CalculateWorkReportsAndAccumulate(
		&newBlock.Header,
		s,
		newTimeState,
		workReports,
	)

	intermediateRecentBlocks := calculateIntermediateBlockState(newBlock.Header, s.RecentBlocks)
	newRecentBlocks, err := calculateNewRecentBlocks(newBlock.Header, newBlock.Extrinsic.EG, intermediateRecentBlocks, serviceHashPairs)
	if err != nil {
		return err
	}

	newJudgements, err := CalculateNewJudgements(newTimeState, newBlock.Extrinsic.ED, s.PastJudgements, s.ValidatorState)
	if err != nil {
		return err
	}

	newCoreAuthorizations := CalculateNewCoreAuthorizations(newBlock.Header, newBlock.Extrinsic.EG, newPendingCoreAuthorizations, s.CoreAuthorizersPool)

	// Update the state with new state values.
	s.TimeslotIndex = newTimeState
	s.EntropyPool = newEntropyPool
	s.ValidatorState = newValidatorState
	s.ValidatorState.QueuedValidators = newQueuedValidators
	s.ValidatorStatistics = newValidatorStatistics
	s.RecentBlocks = newRecentBlocks
	s.CoreAssignments = newCoreAssignments
	s.PastJudgements = newJudgements
	s.CoreAuthorizersPool = newCoreAuthorizations
	s.Services = postAccumulationServiceState
	s.PrivilegedServices = newPrivilegedServices
	s.AccumulationQueue = newAccumulationQueue
	s.AccumulationHistory = newAccumulationHistory

	return nil
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

// preimageHasBeenSolicited R(d, s, h, l) ≡ h ∉ d[s]p ∧ d[s]l[(h, l)] = [] (eq. 12.30)
func preimageHasBeenSolicited(serviceState service.ServiceState, serviceIndex block.ServiceId, preimageHash crypto.Hash, preimageLength service.PreimageLength) bool {
	account, ok := serviceState[serviceIndex]
	if !ok {
		return false
	}
	_, preimageLookupExists := account.PreimageLookup[preimageHash]
	existingMeta := account.PreimageMeta[service.PreImageMetaKey{Hash: preimageHash, Length: preimageLength}]
	return !preimageLookupExists && len(existingMeta) == 0
}

// CalculateIntermediateServiceState Equation 24: δ† ≺ (EP, δ, τ′)
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
func CalculateIntermediateServiceState(preimages block.PreimageExtrinsic, serviceState service.ServiceState, newTimeslot jamtime.Timeslot) service.ServiceState {
	newServiceState := maps.Clone(serviceState)

	for _, preimage := range preimages {
		serviceId := block.ServiceId(preimage.ServiceIndex)
		preimageHash := crypto.HashData(preimage.Data)
		preimageLength := service.PreimageLength(len(preimage.Data))

		// ∀(s, p) ∈ E_P∶ R(δ, s, H(p), |p|) (12.31)
		if !preimageHasBeenSolicited(serviceState, serviceId, preimageHash, preimageLength) {
			continue // preimage has not been solicited
		}

		// let P = {(s, p) | (s, p) ∈ E_P , R(δ‡, s, H(p), |p|)}
		if !preimageHasBeenSolicited(serviceState, serviceId, preimageHash, preimageLength) {
			continue
		}

		// Eq. 12.33:
		//							⎧ δ′[s]p[H(p)] = p
		// δ′ = δ‡ ex. ∀(s, p) ∈ P∶ ⎨
		//							⎩ δ′[s]l[H(p), |p|] = [τ′]
		account, ok := serviceState[serviceId]
		if !ok {
			continue
		}
		// If checks pass, add the new preimage
		if account.PreimageLookup == nil {
			account.PreimageLookup = make(map[crypto.Hash][]byte)
		}
		account.PreimageLookup[preimageHash] = preimage.Data

		if account.PreimageMeta == nil {
			account.PreimageMeta = make(map[service.PreImageMetaKey]service.PreimageHistoricalTimeslots)
		}
		account.PreimageMeta[service.PreImageMetaKey{Hash: preimageHash, Length: preimageLength}] = []jamtime.Timeslot{newTimeslot}

		newServiceState[serviceId] = account
	}

	return newServiceState
}

// CalculateIntermediateCoreAssignmentsFromExtrinsics Equation 25: ρ† ≺ (ED , ρ)
func CalculateIntermediateCoreAssignmentsFromExtrinsics(disputes block.DisputeExtrinsic, coreAssignments state.CoreAssignments) state.CoreAssignments {
	newAssignments := coreAssignments // Create a copy of the current assignments

	// Process each verdict in the disputes
	for _, verdict := range disputes.Verdicts {
		reportHash := verdict.ReportHash
		positiveJudgments := block.CountPositiveJudgments(verdict.Judgements)

		// If less than 2/3 majority of positive judgments, clear the assignment for matching cores
		if positiveJudgments < common.ValidatorsSuperMajority {
			for c := uint16(0); c < common.TotalNumberOfCores; c++ {
				if newAssignments[c] != nil {
					if hash, err := newAssignments[c].WorkReport.Hash(); err == nil && hash == reportHash {
						newAssignments[c] = nil // Clear the assignment
					}
				}
			}
		}
	}

	return newAssignments
}

// CalculateIntermediateCoreAssignmentsFromAvailability implements equation 26: ρ‡ ≺ (EA, ρ†)
// It calculates the intermediate core assignments based on availability assurances.
func CalculateIntermediateCoreAssignmentsFromAvailability(assurances block.AssurancesExtrinsic, coreAssignments state.CoreAssignments, header block.Header) (state.CoreAssignments, []*block.WorkReport, error) {
	// Initialize availability count for each core
	availabilityCounts := make(map[uint16]int)

	// Process each assurance in the AssurancesExtrinsic (EA)
	// Check the availability status for each core in this assurance
	for coreIndex := range common.TotalNumberOfCores {
		for _, assurance := range assurances {
			// Check if the bit corresponding to this core is set (1) in the Bitfield
			if block.HasAssuranceForCore(assurance, coreIndex) {
				if coreAssignments[coreIndex] == nil {
					return coreAssignments, nil, ErrCoreNotEngaged
				}
				// If set, increment the availability count for this core
				availabilityCounts[coreIndex]++
				if isAssignmentStale(coreAssignments[coreIndex], header.TimeSlotIndex) {
					return coreAssignments, nil, ErrReportTimeout
				}
			}
		}
	}

	var removedReports []*block.WorkReport
	// Update assignments based on availability
	// This implements equation 130: ∀c ∈ NC : ρ‡[c] ≡ { ∅ if ρ[c]w ∈ W, ρ†[c] otherwise }
	for coreIndex := range common.TotalNumberOfCores {
		availCountForCore, ok := availabilityCounts[coreIndex]
		// remove core if:
		// 1. there is no availability value for core
		// 2. There is some availability, but it's less than the required threshold
		// 3. Assignment report is stale
		if ok && availCountForCore > common.AvailabilityThreshold {
			removedReports = append(removedReports, coreAssignments[coreIndex].WorkReport)
			coreAssignments[coreIndex] = nil
		}
		if isAssignmentStale(coreAssignments[coreIndex], header.TimeSlotIndex) {
			coreAssignments[coreIndex] = nil
		}
	}

	// Return the new intermediate CoreAssignments (ρ‡)
	return coreAssignments, removedReports, nil
}

// Final State Calculation Functions

// CalculateNewTimeState Equation 16: τ′ ≺ H
func CalculateNewTimeState(header block.Header) jamtime.Timeslot {
	return header.TimeSlotIndex
}

// calculateNewRecentBlocks Equation 18: β′ ≺ (H, EG, β†, C) v0.4.5
func calculateNewRecentBlocks(header block.Header, guarantees block.GuaranteesExtrinsic, intermediateRecentBlocks []state.BlockState, serviceHashPairs ServiceHashPairs) ([]state.BlockState, error) {
	// Gather all the inputs we need.

	// Equation 83: let n = {p, h ▸▸ H(H), b, s ▸▸ H_0}
	headerBytes, err := jam.Marshal(header)
	if err != nil {
		return nil, err
	}
	headerHash := crypto.HashData(headerBytes)

	priorStateRoot := header.PriorStateRoot

	// Equation 83: let r = M_B([s ^^ E_4(s) ⌢ E(h) | (s, h) ∈ C], H_K)
	accumulationRoot, err := computeAccumulationRoot(serviceHashPairs)
	if err != nil {
		return nil, err
	}

	// Equation 83: p = {((g_w)_s)_h ↦ ((g_w)_s)_e | g ∈ E_G}
	workPackageMapping := buildWorkPackageMapping(guarantees.Guarantees)

	// Update β to produce β'.
	newRecentBlocks, err := UpdateRecentBlocks(headerHash, priorStateRoot, accumulationRoot, intermediateRecentBlocks, workPackageMapping)
	if err != nil {
		return nil, err
	}

	return newRecentBlocks, nil
}

// UpdateRecentBlocks updates β. It takes the final inputs from
// Equation 83: let n = {p, h ▸▸ H(H), b, s ▸▸ H_0} and
// produces Equation 84: β′ ≡ ←────── β† n_H.
// We separate out this logic for ease of testing aganist the recent history
// test vectors.
func UpdateRecentBlocks(
	headerHash crypto.Hash,
	priorStateRoot crypto.Hash,
	accumulationRoot crypto.Hash,
	intermediateRecentBlocks []state.BlockState,
	workPackageMapping map[crypto.Hash]crypto.Hash) (newRecentBlocks []state.BlockState, err error) {

	// Equation 82: β†[SβS − 1]s = Hr
	if len(intermediateRecentBlocks) > 0 {
		intermediateRecentBlocks[len(intermediateRecentBlocks)-1].StateRoot = priorStateRoot
	}

	// Equation 83: let b = A(last([[]] ⌢ [x_b | x <− β]), r, H_K)
	var lastBlockMMR []*crypto.Hash
	if len(intermediateRecentBlocks) > 0 {
		lastBlockMMR = intermediateRecentBlocks[len(intermediateRecentBlocks)-1].AccumulationResultMMR
	}
	// Create new MMR instance
	mountainRange := mountain_ranges.New()

	// Append the accumulation root to the MMR using Keccak hash
	// A(last([[]] ⌢ [x_b | x <− β]), r, H_K)
	newMMR := mountainRange.Append(lastBlockMMR, accumulationRoot, crypto.KeccakData)

	newBlockState := state.BlockState{
		HeaderHash:            headerHash,         // h ▸▸ H(H)
		StateRoot:             crypto.Hash{},      // s ▸▸ H_0
		AccumulationResultMMR: newMMR,             // b
		WorkReportHashes:      workPackageMapping, // p
	}

	// Equation 84: β′ ≡ ←────── β† n_H
	// First append new block state
	newRecentBlocks = append(intermediateRecentBlocks, newBlockState)

	// Then keep only last H blocks
	if len(newRecentBlocks) > state.MaxRecentBlocks {
		newRecentBlocks = newRecentBlocks[len(newRecentBlocks)-state.MaxRecentBlocks:]
	}

	return newRecentBlocks, nil
}

// This should create a Merkle tree from the accumulations and return the root ("r" from equation 83, v0.4.5)
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

// Input to UpdateSafroleState. Derived from the incoming block.
type SafroleInput struct {
	// Next timeslot.
	TimeSlot jamtime.Timeslot
	// Ticket extrinsic (E_T).
	Tickets []block.TicketProof
	// Y(Hv)
	Entropy crypto.BandersnatchOutputHash
	// ψ′
	Offenders []ed25519.PublicKey
}

func NewSafroleInputFromBlock(block block.Block) (SafroleInput, error) {
	entropy, err := bandersnatch.OutputHash(block.Header.VRFSignature)
	if err != nil {
		return SafroleInput{}, err
	}

	// TODO - might want to make a deep copy for ticket proofs and offenders
	// here, but should be ok since it's read only.
	return SafroleInput{
		TimeSlot:  block.Header.TimeSlotIndex,
		Tickets:   block.Extrinsic.ET.TicketProofs,
		Entropy:   entropy,
		Offenders: block.Header.OffendersMarkers,
	}, nil
}

// Output from UpdateSafroleState.
type SafroleOutput struct {
	// H_e
	EpochMark *block.EpochMarker
	// H_w
	WinningTicketMark *block.WinningTicketMarker
}

// Validates then produces tickets from submitted ticket proofs.
// Implements equations 74-80 in the graypaper (v.0.4.5)
// ET ∈ D{r ∈ NN, p ∈ F̄[]γz⟨XT ⌢ η′2 r⟩}I  (74)
// |ET| ≤ K if m′ < Y                        (75)
// n ≡ [{y ▸ Y(ip), r ▸ ir} S i <− ET]      (76)
// n = [xy __ x ∈ n]                         (77)
// {xy S x ∈ n} ⫰ {xy S x ∈ γa}             (78)
// γ′a ≡ [xy^^ x ∈ n ∪ {∅ if e′ > e, γa otherwise}]E  (79)
func calculateTickets(safstate safrole.State, entropyPool state.EntropyPool, ticketProofs []block.TicketProof) ([]block.Ticket, error) {
	// Equation 75: |ET| ≤ K if m′ < Y (v.0.4.5)
	if len(ticketProofs) > common.MaxTicketExtrinsicSize {
		return []block.Ticket{}, errors.New("too many tickets")
	}

	ringVerifier, err := safstate.RingVerifier()
	defer ringVerifier.Free()
	if err != nil {
		return []block.Ticket{}, err
	}

	// Equation 78: {xy S x ∈ n} ⫰ {xy S x ∈ γa} (v.0.4.5)
	// Check for duplicate tickets in γ_a
	existingIds := make(map[crypto.BandersnatchOutputHash]struct{}, len(safstate.TicketAccumulator))
	for _, ticket := range safstate.TicketAccumulator {
		existingIds[ticket.Identifier] = struct{}{}
	}
	// Equations 74 and 76 (v.0.4.5)
	// ET ∈ D{r ∈ NN, p ∈ F̄[]γz⟨XT ⌢ η′2 r⟩}I
	// n ≡ [{y ▸ Y(ip), r ▸ ir} S i <− ET]
	tickets := make([]block.Ticket, len(ticketProofs))
	for i, tp := range ticketProofs {
		// Equation 6.29: r ∈ N_N (v.0.5.4)
		if tp.EntryIndex >= common.MaxTicketAttempts {
			return []block.Ticket{}, errors.New("bad ticket attempt")
		}

		// Validate the ring signature. VrfInputData is X_t ⌢ η_2′ ++ r. Equation 74. (v.0.4.5)
		vrfInputData := append([]byte(state.TicketSealContext), entropyPool[2][:]...)
		vrfInputData = append(vrfInputData, tp.EntryIndex)
		// This produces the output hash we need to construct the ticket further down.
		ok, outputHash := ringVerifier.Verify(vrfInputData, []byte{}, safstate.RingCommitment, tp.Proof)
		if !ok {
			return []block.Ticket{}, errors.New("bad ticket proof")
		}

		// Equation 78: {xy S x ∈ n} ⫰ {xy S x ∈ γa} (v.0.4.5)
		if _, exists := existingIds[outputHash]; exists {
			return []block.Ticket{}, errors.New("duplicate ticket")
		}

		// Equation 76: n ≡ [{y ▸ Y(ip), r ▸ ir} S i <− ET] (v.0.4.5)
		tickets[i] = block.Ticket{
			Identifier: outputHash,
			EntryIndex: tp.EntryIndex,
		}
	}

	// Equation 77: n = [xy __ x ∈ n] (v.0.4.5)
	// Verify tickets are ordered by identifier
	for i := 1; i < len(tickets); i++ {
		prevHash := tickets[i-1].Identifier
		currentHash := tickets[i].Identifier
		if bytes.Compare(prevHash[:], currentHash[:]) >= 0 {
			return []block.Ticket{}, errors.New("bad ticket order")
		}
	}

	return tickets, nil
}

// Implements section 6 of the graypaper.
// Updates all state associated with the SAFROLE protocol.
// Implements key equations (v.0.4.5)
// γ′k ≡ Φ(ι) if e′ > e                     (58)
// γ′s ≡ Z(γa) if e′ = e + 1 ∧ m ≥ Y ∧ |γa| = E
//
//	γs if e′ = e
//	F(η′2, κ′) otherwise                (69)
//
// He ≡ (η′1, [kb S k <− γ′k]) if e′ > e
//
//	∅ otherwise                          (72)
//
// Hw ≡ Z(γa) if e′ = e ∧ m < Y ≤ m′ ∧ |γa| = E
//
//	∅ otherwise                          (73)
func UpdateSafroleState(
	input SafroleInput,
	preTimeSlot jamtime.Timeslot,
	entropyPool state.EntropyPool,
	validatorState validator.ValidatorState,
) (state.EntropyPool, validator.ValidatorState, SafroleOutput, error) {
	if input.TimeSlot <= preTimeSlot {
		return entropyPool, validatorState, SafroleOutput{}, errors.New("bad slot")
	}

	nextTimeSlot := input.TimeSlot

	// Equations 67, 68 (v.0.4.5)
	// η′0 ≡ H(η0 ⌢ Y(Hv))
	// (η′1, η′2, η′3) ≡ (η0, η1, η2) if e′ > e
	newEntropyPool, err := calculateNewEntropyPool(preTimeSlot, nextTimeSlot, input.Entropy, entropyPool)
	if err != nil {
		return entropyPool, validatorState, SafroleOutput{}, err
	}

	newValidatorState := validatorState
	output := SafroleOutput{}

	// Process incoming tickets.  Check if we're still allowed to submit
	// tickets. An implication of equation 75. m' < Y to submit.
	if !nextTimeSlot.IsTicketSubmissionPeriod() && len(input.Tickets) > 0 {
		return entropyPool, validatorState, SafroleOutput{}, errors.New("unexpected ticket")
	}

	if len(input.Tickets) > 0 {
		// Validate ticket proofs and produce tickets. Tickets produced are n.
		// As in equation 76.
		tickets, err := calculateTickets(validatorState.SafroleState, entropyPool, input.Tickets)
		if err != nil {
			return entropyPool, validatorState, SafroleOutput{}, err
		}

		// Update the accumulator γ_a.
		// Equation 79: γ′a ≡ [xy^^ x ∈ n ∪ {∅ if e′ > e, γa otherwise}]E (v.0.4.5)
		// Combine existing and new tickets.
		accumulator := validatorState.SafroleState.TicketAccumulator
		allTickets := make([]block.Ticket, len(accumulator)+len(tickets))
		copy(allTickets, accumulator)
		copy(allTickets[len(accumulator):], tickets)

		// Resort by identifier.
		sort.Slice(allTickets, func(i, j int) bool {
			return bytes.Compare(allTickets[i].Identifier[:], allTickets[j].Identifier[:]) < 0
		})

		// Drop older tickets, limiting the accumulator to |E|.
		if len(allTickets) > jamtime.TimeslotsPerEpoch {
			allTickets = allTickets[:jamtime.TimeslotsPerEpoch]
		}

		// Ensure all incoming tickets exist in the accumulator. No useless
		// tickets are allowed. Equation 6.35: n ⊆ γ′a (v.0.5.4)
		existingIds := make(map[crypto.BandersnatchOutputHash]struct{}, len(allTickets))
		for _, ticket := range allTickets {
			existingIds[ticket.Identifier] = struct{}{}
		}
		for _, ticket := range tickets {
			if _, ok := existingIds[ticket.Identifier]; !ok {
				return entropyPool, validatorState, SafroleOutput{}, errors.New("useless ticket")
			}
		}
		newValidatorState.SafroleState.TicketAccumulator = allTickets
	}

	epoch := nextTimeSlot.ToEpoch()   // e'
	preEpoch := preTimeSlot.ToEpoch() // e
	// |γ_a| = E, a condition of equation 73.
	ticketAccumulatorFull := len(validatorState.SafroleState.TicketAccumulator) == jamtime.TimeslotsPerEpoch

	// Note that this condition allows epochs to be skipped, e' > e, as in equations 58, 68, 72. (v.0.4.5)
	// We don't care about the timeslot, only the epoch.
	// Equation 58: (γ′k, κ′, λ′, γ′z) ≡ (Φ(ι), γk, κ, z) if e′ > e
	if epoch > preEpoch {
		// Equation 59: Φ(k) ≡ [0, 0, ...] if ke ∈ ψ′o (v.0.4.5)
		//                     k otherwise
		newValidatorState.SafroleState.NextValidators = validator.NullifyOffenders(validatorState.QueuedValidators, input.Offenders)
		newValidatorState.CurrentValidators = validatorState.SafroleState.NextValidators
		newValidatorState.ArchivedValidators = validatorState.CurrentValidators

		// Calculate new ring commitment. (γ_z) . Apply the O function from equation 58.
		//  Equation 58: z = O([kb S k <− γ′k])
		ringCommitment, err := newValidatorState.SafroleState.CalculateRingCommitment()
		if err != nil {
			return entropyPool, validatorState, SafroleOutput{}, errors.New("unable to calculate ring commitment")
		}
		newValidatorState.SafroleState.RingCommitment = ringCommitment

		// Determine the sealing keys.  Standard way is to use
		// tickets as sealing keys, if we can't then fall back to selecting
		// bandersnatch validator keys for sealing randomly using past entropy.
		// Equation 69: γ′s ≡ Z(γa) if e′ = e + 1 ∧ m ≥ Y ∧ |γa| = E (v.0.4.5)
		//                    γs if e′ = e
		//                    F(η′2, κ′) otherwise
		if epoch == preEpoch+jamtime.Epoch(1) &&
			// m >= Y
			!preTimeSlot.IsTicketSubmissionPeriod() &&
			// |γ_a| = E
			ticketAccumulatorFull {
			// Use tickets for sealing keys. Apply the Z function on the ticket accumulator.
			sealingTickets := safrole.OutsideInSequence(newValidatorState.SafroleState.TicketAccumulator)
			newValidatorState.SafroleState.SealingKeySeries.Set(safrole.TicketsBodies(sealingTickets))
		} else {
			// Use bandersnatch keys for sealing keys.
			fallbackKeys, err := safrole.SelectFallbackKeys(newEntropyPool[2], newValidatorState.CurrentValidators)
			if err != nil {
				return entropyPool, validatorState, SafroleOutput{}, err
			}
			newValidatorState.SafroleState.SealingKeySeries.Set(fallbackKeys)
		}

		// Compute epoch marker (H_e).
		// Equation 6.27: He ≡ (η0, n1, [kb S k <− γ′k]) if e′ > e (v.0.5.4)
		output.EpochMark = &block.EpochMarker{
			Entropy:        entropyPool[0],
			TicketsEntropy: entropyPool[1],
		}
		for i, vd := range newValidatorState.SafroleState.NextValidators {
			output.EpochMark.Keys[i] = vd.Bandersnatch
		}

		// Reset ticket accumulator. From equation 79.
		newValidatorState.SafroleState.TicketAccumulator = []block.Ticket{}
	}

	// Check if we need to generate the winning tickets marker.
	// // Equation 73: Hw ≡ Z(γa) if e′ = e ∧ m < Y ≤ m′ ∧ |γa| = E (v.0.4.5)
	if epoch == preEpoch &&
		nextTimeSlot.IsWinningTicketMarkerPeriod(preTimeSlot) &&
		ticketAccumulatorFull {
		// Apply the Z function to the ticket accumulator.
		winningTickets := safrole.OutsideInSequence(newValidatorState.SafroleState.TicketAccumulator)
		output.WinningTicketMark = (*block.WinningTicketMarker)(winningTickets)
	}

	return newEntropyPool, newValidatorState, output, nil
}

// Implements equations 67 and 68 from the graypaper. (v.0.4.5)
// The entropyInput is assumed to be bandersnatch output hash from the block vrf siganture, Y(Hv).
// The entryPool is defined as equation 66.
// Calculates η′0 ≡ H(η0 ⌢ Y(Hv)) every slot, and rotates the entropies on epoch change.
func calculateNewEntropyPool(currentTimeslot jamtime.Timeslot, newTimeslot jamtime.Timeslot, entropyInput crypto.BandersnatchOutputHash, entropyPool state.EntropyPool) (state.EntropyPool, error) {
	newEntropyPool := entropyPool

	if newTimeslot.ToEpoch() > currentTimeslot.ToEpoch() {
		newEntropyPool = rotateEntropyPool(entropyPool)
	}

	newEntropyPool[0] = crypto.HashData(append(entropyPool[0][:], entropyInput[:]...))
	return newEntropyPool, nil
}

func rotateEntropyPool(pool state.EntropyPool) state.EntropyPool {
	pool[3] = pool[2]
	pool[2] = pool[1]
	pool[1] = pool[0]
	return pool
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

// calculateNewJudgements Equation 23: ψ′ ≺ (ED, ψ)
// Equations 112-115:(v0.4.5)
// ψ'g ≡ ψg ∪ {r | {r, ⌊2/3V⌋ + 1} ∈ V}
// ψ'b ≡ ψb ∪ {r | {r, 0} ∈ V}
// ψ'w ≡ ψw ∪ {r | {r, ⌊1/3V⌋} ∈ V}
// ψ'o ≡ ψo ∪ {k | (r, k, s) ∈ c} ∪ {k | (r, v, k, s) ∈ f}
func CalculateNewJudgements(newTimeslot jamtime.Timeslot, disputes block.DisputeExtrinsic, stateJudgements state.Judgements, validators validator.ValidatorState) (state.Judgements, error) {
	if err := verifySortedUnique(disputes); err != nil {
		return stateJudgements, err
	}

	if err := verifyAllSignatures(newTimeslot, disputes, validators); err != nil {
		return stateJudgements, err
	}

	if err := verifyNotAlreadyOffending(disputes.Faults, stateJudgements.OffendingValidators); err != nil {
		return stateJudgements, err
	}

	if err := verifyNotAlreadyJudged(disputes.Verdicts, stateJudgements); err != nil {
		return stateJudgements, err
	}

	newJudgements := copyJudgements(stateJudgements)

	if err := verifyFaults(disputes.Faults, disputes.Verdicts, stateJudgements.OffendingValidators); err != nil {
		return stateJudgements, err
	}

	if err := processVerdicts(disputes, &newJudgements); err != nil {
		return stateJudgements, err
	}

	if err := processCulprits(disputes.Culprits, disputes.Verdicts, &newJudgements); err != nil {
		return stateJudgements, err
	}

	return newJudgements, nil
}

// Equation 101:(v0.4.5)
// ∀(r, k, s) ∈ c : ⋀{r ∈ ψ'b, k ∈ k, s ∈ Ek⟨XG ⌢ r⟩}
func verifyNotAlreadyOffending(faults []block.Fault, offendingValidators []ed25519.PublicKey) error {
	for _, fault := range faults {
		if containsKey(offendingValidators, fault.ValidatorEd25519PublicKey) {
			return errors.New("offender already reported")
		}
	}
	return nil
}

// Equations 103, 104, 106:(v0.4.5)
// v = [r __ {r, a, j} ∈ v]  (Verdicts must be ordered by report hash)
// c = [k __ {r, k, s} ∈ c]  (Culprits must be ordered by validator key)
// f = [k __ {r, v, k, s} ∈ f]  (Faults must be ordered by validator key)
// ∀(r, a, j) ∈ v : j = [i __ {v, i, s} ∈ j]  (Judgments within verdicts must be ordered by validator index)
func verifyNotAlreadyJudged(verdicts []block.Verdict, stateJudgements state.Judgements) error {
	for _, verdict := range verdicts {
		reportHash := verdict.ReportHash
		if contains(stateJudgements.GoodWorkReports, reportHash) ||
			contains(stateJudgements.BadWorkReports, reportHash) ||
			contains(stateJudgements.WonkyWorkReports, reportHash) {
			return errors.New("already judged")
		}
	}
	return nil
}

func copyJudgements(stateJudgements state.Judgements) state.Judgements {
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

	return newJudgements
}

// Equations 109, 110, 111:(v0.4.5)
// ∀(r, ⌊2/3V⌋ + 1) ∈ V : ∃(r, ...) ∈ f  (For positive verdicts, must have corresponding fault)
// ∀(r, 0) ∈ V : |{(r, ...) ∈ c}| ≥ 2  (For negative verdicts, must have at least 2 culprits)
//
//	∀c ∈ NC : ρ†[c] = {
//	    ∅ if {(H(ρ[c]w), t) ∈ V, t < ⌊2/3V⌋}
//	    ρ[c] otherwise
//	}
func processVerdicts(disputes block.DisputeExtrinsic, newJudgements *state.Judgements) error {
	const V = common.NumberOfValidators // Total number of validators
	twoThirdsPlusOne := (2 * V / 3) + 1 // ⌊2/3V⌋ + 1
	oneThird := V / 3                   // ⌊1/3V⌋

	for _, verdict := range disputes.Verdicts {
		positiveJudgments := block.CountPositiveJudgments(verdict.Judgements)

		switch positiveJudgments {
		case twoThirdsPlusOne:
			if err := processPositiveVerdict(verdict, disputes.Faults, newJudgements); err != nil {
				return err
			}

		case 0:
			if err := processNegativeVerdict(verdict, disputes.Culprits, newJudgements); err != nil {
				return err
			}

		case oneThird:
			processWonkyVerdict(verdict, newJudgements)

		default:
			return fmt.Errorf("bad vote split")
		}
	}

	return nil
}

// Equations 109, 110:(v0.4.5)
// ∀(r, ⌊2/3V⌋ + 1) ∈ V : ∃(r, ...) ∈ f
func processPositiveVerdict(verdict block.Verdict, faults []block.Fault, newJudgements *state.Judgements) error {
	validFaults := 0
	for _, fault := range faults {
		if fault.ReportHash != verdict.ReportHash || fault.IsValid {
			continue
		}
		validFaults++
		if !containsKey(newJudgements.OffendingValidators, fault.ValidatorEd25519PublicKey) {
			newJudgements.OffendingValidators = append(newJudgements.OffendingValidators, fault.ValidatorEd25519PublicKey)
		}
	}

	if validFaults == 0 {
		return errors.New("not enough faults")
	}

	newJudgements.GoodWorkReports = append(newJudgements.GoodWorkReports, verdict.ReportHash)
	return nil
}

// Related to Equation 110:(v0.4.5)
// ∀(r, 0) ∈ V : |{(r, ...) ∈ c}| ≥ 2
func processNegativeVerdict(verdict block.Verdict, culprits []block.Culprit, newJudgements *state.Judgements) error {
	if len(culprits) < 2 {
		return errors.New("not enough culprits")
	}
	newJudgements.BadWorkReports = append(newJudgements.BadWorkReports, verdict.ReportHash)
	return nil
}

// Related to Equation 114:(v0.4.5)
// ψ'w ≡ ψw ∪ {r | {r, ⌊1/3V⌋} ∈ V}
func processWonkyVerdict(verdict block.Verdict, newJudgements *state.Judgements) {
	newJudgements.WonkyWorkReports = append(newJudgements.WonkyWorkReports, verdict.ReportHash)
}

// Equations 101, 102, 104, 105: (v0.4.5)
// c = [k __ {r, k, s} ∈ c]  (Culprits must be ordered)
//
//	∀(r, k, s) ∈ c : ⋀{
//	    r ∈ ψ'b,  (Report must be in bad reports)
//	    k ∈ k,    (Key must be valid validator)
//	    s ∈ Ek⟨XG ⌢ r⟩  (Signature must be valid)
//	}
//
//	∀(r, v, k, s) ∈ f : ⋀{
//	    r ∈ ψ'b ⇔ r ∉ ψ'g ⇔ v,
//	    k ∈ k,
//	    s ∈ Ek⟨Xv ⌢ r⟩
//	}
//
// {r | {r, a, j} ∈ v} ⫰ ψg ∪ ψb ∪ ψw  (Reports must not have been previously judged)
func processCulprits(culprits []block.Culprit, verdicts []block.Verdict, newJudgements *state.Judgements) error {
	for _, culprit := range culprits {
		// Find corresponding verdict
		var allNegative bool
		for _, verdict := range verdicts {
			if verdict.ReportHash == culprit.ReportHash {
				// Check if all votes are false
				positiveJudgments := block.CountPositiveJudgments(verdict.Judgements)
				if positiveJudgments > 0 {
					return errors.New("bad vote split")
				}
				allNegative = true
				break
			}
		}
		if !allNegative {
			return errors.New("culprits verdict not bad")
		}
	}

	// Process culprits
	if err := verifyCulprits(culprits, newJudgements.BadWorkReports, newJudgements.OffendingValidators); err != nil {
		return err
	}

	for _, culprit := range culprits {
		if !containsKey(newJudgements.OffendingValidators, culprit.ValidatorEd25519PublicKey) {
			newJudgements.OffendingValidators = append(newJudgements.OffendingValidators, culprit.ValidatorEd25519PublicKey)
		}
	}

	return nil
}

// Equations 103, 104, 106:
// v = [r __ {r, a, j} ∈ v]  (Verdicts must be ordered by report hash)
// c = [k __ {r, k, s} ∈ c]  (Faults must be ordered by validator key)
// f = [k __ {r, v, k, s} ∈ f]  (Faults must be ordered by validator key)
// ∀(r, a, j) ∈ v : j = [i __ {v, i, s} ∈ j]  (Judgments within verdicts must be ordered by validator index)
func verifySortedUnique(disputes block.DisputeExtrinsic) error {
	// Check faults are sorted unique
	for i := 1; i < len(disputes.Faults); i++ {
		if bytes.Compare(disputes.Faults[i-1].ValidatorEd25519PublicKey, disputes.Faults[i].ValidatorEd25519PublicKey) >= 0 {
			return errors.New("faults not sorted unique")
		}
	}

	// Check verdicts are sorted unique
	for i := 1; i < len(disputes.Verdicts); i++ {
		if bytes.Compare(disputes.Verdicts[i-1].ReportHash[:], disputes.Verdicts[i].ReportHash[:]) >= 0 {
			return errors.New("verdicts not sorted unique")
		}
	}

	// Check judgements within verdicts are sorted unique
	for _, verdict := range disputes.Verdicts {
		for i := 1; i < len(verdict.Judgements); i++ {
			if verdict.Judgements[i-1].ValidatorIndex >= verdict.Judgements[i].ValidatorIndex {
				return errors.New("judgements not sorted unique")
			}
		}
	}

	return nil
}

// Related to Equation 99:(v0.4.5)
// ∀(r, a, j) ∈ v, ∀(v, i, s) ∈ j : s ∈ Ek[i]e⟨Xv ⌢ r⟩
func verifyAllSignatures(newTimeslot jamtime.Timeslot, disputes block.DisputeExtrinsic, validators validator.ValidatorState) error {
	// Verify verdict signatures
	for _, verdict := range disputes.Verdicts {
		if err := verifyVerdictSignatures(newTimeslot, verdict, validators.CurrentValidators, validators.ArchivedValidators); err != nil {
			return err
		}
	}

	// Verify culprit signatures
	for _, culprit := range disputes.Culprits {
		message := append([]byte(state.SignatureContextGuarantee), culprit.ReportHash[:]...)
		if !ed25519.Verify(culprit.ValidatorEd25519PublicKey, message, culprit.Signature[:]) {
			return errors.New("bad signature")
		}
	}

	// Verify fault signatures
	for _, fault := range disputes.Faults {
		context := state.SignatureContextValid
		if !fault.IsValid {
			context = state.SignatureContextInvalid
		}
		message := append([]byte(context), fault.ReportHash[:]...)
		if !ed25519.Verify(fault.ValidatorEd25519PublicKey, message, fault.Signature[:]) {
			return errors.New("bad signature")
		}
	}

	return nil
}

// Related to Equation 99:(v0.4.5)
// ∀(r, a, j) ∈ v, ∀(v, i, s) ∈ j :
// s ∈ Ek[i]e⟨Xv ⌢ r⟩ where k = κ if a = ⌊τ/E⌋, λ otherwise
func verifyVerdictSignatures(newTimeslot jamtime.Timeslot, verdict block.Verdict, currentValidators, archivedValidators safrole.ValidatorsData) error {
	currentEpoch := uint32(newTimeslot.ToEpoch())
	validatorSet := currentValidators
	if verdict.EpochIndex != currentEpoch {
		validatorSet = archivedValidators
	}

	// Verify signatures before checking age
	for _, judgment := range verdict.Judgements {
		if judgment.ValidatorIndex >= uint16(len(validatorSet)) {
			return errors.New("invalid validator index")
		}

		context := state.SignatureContextValid
		if !judgment.IsValid {
			context = state.SignatureContextInvalid
		}

		message := append([]byte(context), verdict.ReportHash[:]...)

		if !ed25519.Verify(validatorSet[judgment.ValidatorIndex].Ed25519, message, judgment.Signature[:]) {
			return errors.New("bad signature")
		}
	}
	// Age checks come after signature verification
	if verdict.EpochIndex > currentEpoch {
		return errors.New("bad judgement age")
	}
	if currentEpoch-verdict.EpochIndex > 1 {
		return errors.New("bad judgement age")
	}

	return nil
}

// Related to Equations 101, 102:(v0.4.5)
// ∀(r, k, s) ∈ c : ⋀{r ∈ ψ'b, k ∈ k, s ∈ Ek⟨XG ⌢ r⟩}
// ∀(r, v, k, s) ∈ f : ⋀{r ∈ ψ'b ⇔ r ∉ ψ'g ⇔ v, k ∈ k, s ∈ Ek⟨Xv ⌢ r⟩}
func verifyCulprits(culprits []block.Culprit, badReports []crypto.Hash, offendingValidators []ed25519.PublicKey) error {
	for i := 1; i < len(culprits); i++ {
		if bytes.Compare(culprits[i-1].ValidatorEd25519PublicKey, culprits[i].ValidatorEd25519PublicKey) >= 0 {
			return errors.New("culprits not sorted unique")
		}
	}
	for _, culprit := range culprits {
		// Verify guarantee signature
		message := append([]byte(state.SignatureContextGuarantee), culprit.ReportHash[:]...)
		if !ed25519.Verify(culprit.ValidatorEd25519PublicKey, message, culprit.Signature[:]) {
			return errors.New("bad signature")
		}
		// Must be in bad reports
		if !contains(badReports, culprit.ReportHash) {
			return errors.New("culprits verdict not bad")
		}

		// Must not already be in offending validators
		if containsKey(offendingValidators, culprit.ValidatorEd25519PublicKey) {
			return errors.New("offender already reported")
		}
	}
	return nil
}

// Related to Equations 101, 102:(v0.4.5)
// ∀(r, k, s) ∈ c : ⋀{r ∈ ψ'b, k ∈ k, s ∈ Ek⟨XG ⌢ r⟩}
// ∀(r, v, k, s) ∈ f : ⋀{r ∈ ψ'b ⇔ r ∉ ψ'g ⇔ v, k ∈ k, s ∈ Ek⟨Xv ⌢ r⟩}
func verifyFaults(faults []block.Fault, verdicts []block.Verdict, offendingValidators []ed25519.PublicKey) error {
	for _, fault := range faults {
		// Find corresponding verdict
		var allPositive bool
		for _, verdict := range verdicts {
			if verdict.ReportHash == fault.ReportHash {
				positiveJudgments := block.CountPositiveJudgments(verdict.Judgements)
				allPositive = positiveJudgments == len(verdict.Judgements)
				break
			}
		}

		// Fault vote should be opposite to verdict
		// If verdict is all positive, fault vote should be false
		// If verdict is all negative, fault vote should be true
		if fault.IsValid == allPositive {
			return errors.New("fault verdict wrong")
		}

		// Check that validator isn't already offending
		if containsKey(offendingValidators, fault.ValidatorEd25519PublicKey) {
			return errors.New("offender already reported")
		}

		// Verify signature
		context := state.SignatureContextValid
		if !fault.IsValid {
			context = state.SignatureContextInvalid
		}
		message := append([]byte(context), fault.ReportHash[:]...)
		if !ed25519.Verify(fault.ValidatorEd25519PublicKey, message, fault.Signature[:]) {
			return errors.New("bad signature")
		}
	}
	return nil
}

func contains(slice []crypto.Hash, item crypto.Hash) bool {
	for _, hash := range slice {
		if hash == item {
			return true
		}
	}
	return false
}

func containsKey(slice []ed25519.PublicKey, key ed25519.PublicKey) bool {
	for _, k := range slice {
		if bytes.Equal(k, key) {
			return true
		}
	}
	return false
}

// CalculateNewCoreAssignments updates the core assignments based on new guarantees.
// This implements equation 27: ρ′ ≺ (EG, ρ‡, κ, τ′)
//
// It also implements part of equation 11.26 v0.6.2 regarding timeslot validation:
// R(⌊τ′/R⌋ - 1) ≤ t ≤ τ′
func CalculateNewCoreAssignments(
	guarantees block.GuaranteesExtrinsic,
	intermediateAssignments state.CoreAssignments,
	validatorState validator.ValidatorState,
	newTimeslot jamtime.Timeslot,
	entropyPool state.EntropyPool,
) (newAssignments state.CoreAssignments, reporters crypto.ED25519PublicKeySet, err error) {
	newAssignments = intermediateAssignments
	reporters = make(crypto.ED25519PublicKeySet)

	for _, guarantee := range guarantees.Guarantees {
		coreIndex := guarantee.WorkReport.CoreIndex
		log.Printf("Processing guarantee for core %d", coreIndex)

		// Check timeslot range: R(⌊τ′/R⌋ - 1) ≤ t ≤ τ′
		previousRotationStart := (newTimeslot/common.ValidatorRotationPeriod - 1) * common.ValidatorRotationPeriod

		if guarantee.Timeslot < previousRotationStart ||
			guarantee.Timeslot > newTimeslot {
			return state.CoreAssignments{}, nil, ErrTimeslotOutOfRange
		}

		if isAssignmentValid(intermediateAssignments[coreIndex], newTimeslot) {
			var guaranteeReporters crypto.ED25519PublicKeySet
			guaranteeReporters, err := verifyGuaranteeCredentials(guarantee, validatorState, entropyPool, newTimeslot)
			if err != nil {
				log.Printf("Signature verification failed for core %d", guarantee.WorkReport.CoreIndex)
				return state.CoreAssignments{}, nil, err
			}
			for reporter := range guaranteeReporters {
				reporters[reporter] = struct{}{}
			}

			newAssignments[coreIndex] = &state.Assignment{
				WorkReport: &guarantee.WorkReport,
				Time:       newTimeslot,
			}
		}
	}

	return newAssignments, reporters, nil
}

// generateRefinementContextID serializes the RefinementContext and returns its SHA-256 hash as a hex string.
func generateRefinementContextID(context block.RefinementContext) (string, error) {
	serialized, err := jam.Marshal(context)
	if err != nil {
		return "", fmt.Errorf("failed to serialize RefinementContext: %w", err)
	}

	hash := sha256.Sum256(serialized)

	// Convert hash to a hex
	return fmt.Sprintf("%x", hash), nil
}

// computeWorkReportHash computes a SHA-256 hash of the WorkReport
func computeWorkReportHash(workReport block.WorkReport) (crypto.Hash, error) {
	serialized, err := jam.Marshal(workReport)
	if err != nil {
		return crypto.Hash{}, fmt.Errorf("failed to serialize WorkReport: %w", err)
	}
	hash := sha256.Sum256(serialized)

	return hash, nil
}

func ValidateExtrinsicGuarantees(
	header block.Header,
	currentState *state.State,
	guarantees block.GuaranteesExtrinsic,
	currentAssignment state.CoreAssignments,
	newTimeslot jamtime.Timeslot,
	chain *store.Chain,
) error {
	// [⋃ x∈β] K(x_p) ∪ [⋃ x∈ξ] x ∪ q ∪ a
	pastWorkPackages := make(map[crypto.Hash]struct{})

	// [⋃ x∈β] K(xp)
	recentBlockPrerequisites := make(map[crypto.Hash]crypto.Hash)

	for _, recentBlock := range currentState.RecentBlocks {
		for key, val := range recentBlock.WorkReportHashes {
			recentBlockPrerequisites[key] = val
			pastWorkPackages[key] = struct{}{}
		}
	}

	seenPackages := make(map[crypto.Hash]struct{})
	for _, guarantee := range guarantees.Guarantees {
		hash := guarantee.WorkReport.WorkPackageSpecification.WorkPackageHash
		if _, exists := seenPackages[hash]; exists {
			return fmt.Errorf("duplicate package")
		}
		if _, exists := pastWorkPackages[hash]; exists {
			return fmt.Errorf("duplicate package")
		}
		seenPackages[hash] = struct{}{}
	}

	for _, guarantee := range guarantees.Guarantees {
		if guarantee.Timeslot > header.TimeSlotIndex {
			return errors.New("future report slot")
		}

		for _, credential := range guarantee.Credentials {
			if int(credential.ValidatorIndex) >= len(currentState.ValidatorState.CurrentValidators) {
				return fmt.Errorf("bad validator index")
			}
		}

		for _, workResult := range guarantee.WorkReport.WorkResults {
			// validate service ID exist
			if _, exists := currentState.Services[workResult.ServiceId]; !exists {
				return errors.New("bad service id")
			}
			// ∀w ∈ w, ∀r ∈ wr ∶ rc = δ[rs]c (eq. 11.41 0.5.0)
			if workResult.ServiceHashCode != currentState.Services[workResult.ServiceId].CodeHash {
				return errors.New("bad code hash")
			}
		}

		// Validate core index is within bounds based on auth pools length
		if int(guarantee.WorkReport.CoreIndex) >= len(currentState.CoreAuthorizersPool) {
			return errors.New("bad core index")
		}

		// Size check for Work Report output
		if !guarantee.WorkReport.OutputSizeIsValid() {
			return errors.New("work report too big")
		}

		// Verify authorizer exists in the core's authorization pool
		authFound := false
		for _, auth := range currentState.CoreAuthorizersPool[guarantee.WorkReport.CoreIndex] {
			if auth == guarantee.WorkReport.AuthorizerHash {
				authFound = true
				break
			}
		}
		if !authFound {
			return errors.New("core unauthorized")
		}

		// check if cores are already engaged
		coreIndex := guarantee.WorkReport.CoreIndex
		if !isAssignmentValid(currentAssignment[coreIndex], newTimeslot) {
			return errors.New("core engaged")
		}

	}

	contexts := make(map[string]struct{})
	extrinsicWorkPackages := make(map[crypto.Hash]crypto.Hash)

	prerequisitePackageHashes := make(map[crypto.Hash]struct{})

	for _, guarantee := range guarantees.Guarantees {
		context := guarantee.WorkReport.RefinementContext

		// Generate a unique ID for the context
		contextID, err := generateRefinementContextID(context)
		if err != nil {
			return fmt.Errorf("failed to generate RefinementContextID: %w", err)
		}

		contexts[contextID] = struct{}{}
		extrinsicWorkPackages[guarantee.WorkReport.WorkPackageSpecification.WorkPackageHash] = guarantee.WorkReport.WorkPackageSpecification.SegmentRoot
		// ∀w ∈ w ∶ [∑ r∈wr] (rg) ≤ GA ∧ ∀r ∈ wr ∶ rg ≥ δ[rs]g (eq. 11.29 0.5.0)
		totalGas := uint64(0)
		for _, r := range guarantee.WorkReport.WorkResults {
			if r.GasPrioritizationRatio < currentState.Services[r.ServiceId].GasLimitForAccumulator {
				return fmt.Errorf("service item gas too low")
			}
			totalGas += r.GasPrioritizationRatio
		}
		if totalGas > common.MaxAllocatedGasAccumulation {
			return fmt.Errorf("work report gas too high")
		}

		for key := range guarantee.WorkReport.SegmentRootLookup {
			prerequisitePackageHashes[key] = struct{}{}
		}

		// Check total dependencies. 11.3 GP 0.5.4
		totalDeps := len(guarantee.WorkReport.RefinementContext.PrerequisiteWorkPackage) +
			len(guarantee.WorkReport.SegmentRootLookup)
		if totalDeps > common.WorkReportMaxSumOfDependencies {
			return errors.New("too many dependencies")
		}

		for _, prereqHash := range context.PrerequisiteWorkPackage {
			prerequisitePackageHashes[prereqHash] = struct{}{}

			// let q = {(wx)p S q ∈ ϑ, w ∈ K(q)} (eq. 11.35 0.5.0)
			for _, workReportsAndDeps := range currentState.AccumulationQueue {
				for _, wd := range workReportsAndDeps {
					// Compare the hashes
					wdHash, err := computeWorkReportHash(wd.WorkReport)
					if err != nil {
						return fmt.Errorf("failed to compute WorkReport hash: %w", err)
					}
					currentGuaranteeHash, err := computeWorkReportHash(guarantee.WorkReport)
					if err != nil {
						return fmt.Errorf("failed to compute current WorkReport hash: %w", err)
					}
					if wdHash == currentGuaranteeHash {
						pastWorkPackages[prereqHash] = struct{}{}
					}
				}
			}
		}

		// let a = {((iw )x)p S i ∈ ρ, i ≠ ∅} (eq. 11.36 0.5.0)
		for _, ca := range currentState.CoreAssignments {
			if ca != nil && ca.WorkReport != nil {
				for _, prereqHash := range ca.WorkReport.RefinementContext.PrerequisiteWorkPackage {
					pastWorkPackages[prereqHash] = struct{}{}
				}
			}
		}
	}

	// |p| = |w| (eq. 11.31 0.5.0)
	if len(extrinsicWorkPackages) != len(guarantees.Guarantees) {
		return fmt.Errorf("cardinality of work-package hashes is not equal to the length of work-reports")
	}

	for _, guarantee := range guarantees.Guarantees {
		context := guarantee.WorkReport.RefinementContext
		contextID, err := generateRefinementContextID(context)
		if err != nil {
			return fmt.Errorf("failed to generate RefinementContextID: %w", err)
		}

		if _, exists := contexts[contextID]; !exists {
			return fmt.Errorf("context ID not found in contexts map")
		}

		// ∀x ∈ x ∶ ∃y ∈ β ∶ x_a = y_h ∧ x_s = y_s ∧ x_b = HK (EM (y_b)) (eq. 11.32 0.5.0)
		found, err := anchorBlockInRecentBlocks(context, currentState)
		if !found {
			return err
		}

		// ∀x ∈ x ∶ xt ≥ Ht − L (eq. 11.33 0.5.0)
		if context.LookupAnchor.Timeslot >= header.TimeSlotIndex-state.MaxTimeslotsForPreimage {
			return fmt.Errorf("lookup anchor block (timeslot %d) not within the last %d timeslots (current timeslot: %d)", context.LookupAnchor.Timeslot, state.MaxTimeslotsForPreimage, header.TimeSlotIndex)
		}

		// ∀x ∈ x ∶ ∃h ∈ A ∶ ht = xt ∧ H(h) = xl (eq. 11.34 0.5.0)
		_, err = chain.FindHeader(func(ancestor block.Header) bool {
			ancestorHash, err := ancestor.Hash()
			if err != nil {
				return false
			}
			return ancestor.TimeSlotIndex == context.LookupAnchor.Timeslot && ancestorHash == context.LookupAnchor.HeaderHash
		})
		if err != nil {
			return fmt.Errorf("no record of header found: %w", err)
		}
	}

	accHistoryPrerequisites := make(map[crypto.Hash]struct{})
	for _, hashSet := range currentState.AccumulationHistory {
		maps.Copy(accHistoryPrerequisites, hashSet)
	}

	// ∀p ∈ p, p ∉ [⋃ x∈β] K(x_p) ∪ [⋃ x∈ξ] x ∪ q ∪ a (eq. 11.37 0.5.0)
	for p := range extrinsicWorkPackages {
		if _, ok := pastWorkPackages[p]; ok {
			return fmt.Errorf("report work-package is the work-package of some other report made in the past")
		}
	}

	// p ∪ {x | x ∈ b_p, b ∈ β} (eq. 11.33, 11.39 0.5.0)
	extrinsicAndRecentWorkPackages := make(map[crypto.Hash]crypto.Hash)
	for k, v := range extrinsicWorkPackages {
		extrinsicAndRecentWorkPackages[k] = v
	}
	for k, v := range recentBlockPrerequisites {
		extrinsicAndRecentWorkPackages[k] = v
	}

	for _, guarantee := range guarantees.Guarantees {
		// ∀w ∈ w ∶ wl ⊆ p ∪ [⋃ b∈β] b_p (eq. 11.40 0.5.0)
		for lookupKey, lookupValue := range guarantee.WorkReport.SegmentRootLookup {
			if extrinsicAndRecentWorkPackages[lookupKey] != lookupValue {
				return fmt.Errorf("segment root lookup invalid")
			}
		}
	}

	// Add recent block work packages to the allowed set
	for _, block := range currentState.RecentBlocks {
		for hash := range block.WorkReportHashes {
			extrinsicWorkPackages[hash] = block.WorkReportHashes[hash]
		}
	}

	// ∀w ∈ w, ∀p ∈ (wx)p ∪ K(wl) ∶ p ∈ p ∪ {x S x ∈ K(bp), b ∈ β} (eq. 11.38 0.5.0)
	for p := range prerequisitePackageHashes {
		if _, ok := extrinsicWorkPackages[p]; !ok {
			return fmt.Errorf("dependency missing")
		}
	}

	if !isGuaranteesSortedByCoreIndex(guarantees.Guarantees) {
		return errors.New("out of order guarantee")
	}
	for _, guarantee := range guarantees.Guarantees {
		// ∀w ∈ w ∶ wl ⊆ p ∪ [⋃ b∈β] b_p (eq. 11.40 0.5.0)
		for lookupKey, lookupValue := range guarantee.WorkReport.SegmentRootLookup {
			if extrinsicAndRecentWorkPackages[lookupKey] != lookupValue {
				return fmt.Errorf("segment root lookup invalid")
			}
		}
		// Verify that credentials are ordered by validator index (equation 11.24 0.5.0)
		for i := 1; i < len(guarantee.Credentials); i++ {
			if guarantee.Credentials[i-1].ValidatorIndex >= guarantee.Credentials[i].ValidatorIndex {
				return errors.New("not sorted or unique guarantors")
			}
		}

		// Check each individual guarantee has at least 2 signatures:
		// From Graypaper 0.5.0: "With two guarantor signatures, the work-report may be distributed"
		if len(guarantee.Credentials) < 2 {
			return fmt.Errorf("insufficient guarantees")
		}

		err := verifyGuaranteeAge(guarantee, newTimeslot)
		if err != nil {
			return err
		}
	}

	return nil
}

// anchorBlockInRecentBlocks ∀x ∈ x ∶ ∃y ∈ β ∶ x_a = y_h ∧ x_s = ys ∧ xb = M_R (yb)) (11.34 v0.5.2)
func anchorBlockInRecentBlocks(context block.RefinementContext, currentState *state.State) (bool, error) {
	for _, y := range currentState.RecentBlocks {
		if context.Anchor.HeaderHash != y.HeaderHash {
			continue
		}

		// Found block but state root doesn't match
		if context.Anchor.PosteriorStateRoot != y.StateRoot {
			return false, fmt.Errorf("bad state root")
		}

		// Block found, check MMR
		mountainRange := mountain_ranges.New()
		beefyRoot := mountainRange.SuperPeak(y.AccumulationResultMMR, crypto.KeccakData)
		if context.Anchor.PosteriorBeefyRoot == beefyRoot {
			return true, nil
		}

		// Found block but beefy root doesn't match
		return false, fmt.Errorf("bad beefy mmr root")
	}
	// No matching block found
	return false, fmt.Errorf("anchor not recent")
}

// determineValidatorsAndDataForPermutation implements relevant data selection from equation 11.20 and 11.21 in GP 0.5.0:
// Equation 11.20:
//
//	G ≡ (P(η₂', τ'), Φ(κ'))
//
// Equation 11.21:
//
//	G* ≡ (P(e, τ' - R), Φ(k))
//	where (e,k) = {
//	  (η₂', κ') if ⌊(τ'-R)/E⌋ = ⌊τ'/E⌋
//	  (η₃', λ') otherwise
//	}
func determineValidatorsAndDataForPermutation(
	guaranteeTimeslot jamtime.Timeslot,
	currentTimeslot jamtime.Timeslot,
	entropyPool state.EntropyPool,
	currentValidators safrole.ValidatorsData,
	archivedValidators safrole.ValidatorsData,
) (safrole.ValidatorsData, crypto.Hash, jamtime.Timeslot) {
	currentRotation := currentTimeslot / common.ValidatorRotationPeriod
	guaranteeRotation := guaranteeTimeslot / common.ValidatorRotationPeriod

	var entropy crypto.Hash
	var timeslotForPermutation jamtime.Timeslot
	var validators safrole.ValidatorsData

	// G ≡ (P(η₂', τ'), Φ(κ')) for current rotation
	if guaranteeRotation == currentRotation {
		entropy = entropyPool[2]
		timeslotForPermutation = currentTimeslot
		validators = currentValidators
	} else {
		timeslotForPermutation = currentTimeslot - common.ValidatorRotationPeriod
		currentEpochIndex := currentTimeslot / jamtime.TimeslotsPerEpoch
		prevEpochIndex := timeslotForPermutation / jamtime.TimeslotsPerEpoch

		// G* ≡ (P(e, τ' - R), Φ(k)) for previous rotation
		if currentEpochIndex == prevEpochIndex {
			entropy = entropyPool[2]
			validators = currentValidators
		} else {
			entropy = entropyPool[3]
			validators = archivedValidators
		}
	}

	return validators, entropy, timeslotForPermutation
}

// isGuaranteesSortedByCoreIndex checks if the guarantees are sorted by their core index
// in ascending order, implementing the ordering requirement from equation 137
// in the graypaper: EG = [(gw)c ^ g ∈ EG]
func isGuaranteesSortedByCoreIndex(guarantees []block.Guarantee) bool {
	if len(guarantees) <= 1 {
		return true
	}

	for i := 0; i < len(guarantees)-1; i++ {
		currentIndex := guarantees[i].WorkReport.CoreIndex
		nextIndex := guarantees[i+1].WorkReport.CoreIndex

		if currentIndex >= nextIndex {
			return false
		}
	}

	return true
}

// isAssignmentValid checks if a new assignment can be made for a core.
// This implements the condition from equation 142:
// ρ‡[wc] = ∅ ∨ Ht ≥ ρ‡[wc]t + U
func isAssignmentValid(currentAssignment *state.Assignment, newTimeslot jamtime.Timeslot) bool {
	return currentAssignment == nil || (currentAssignment.WorkReport == nil || isAssignmentStale(currentAssignment, newTimeslot))
}

func isAssignmentStale(currentAssignment *state.Assignment, newTimeslot jamtime.Timeslot) bool {
	return currentAssignment != nil && newTimeslot >= currentAssignment.Time+common.WorkReportTimeoutPeriod
}

func verifyGuaranteeAge(guarantee block.Guarantee, currentTimeslot jamtime.Timeslot) error {
	guaranteeRotation := guarantee.Timeslot / common.ValidatorRotationPeriod
	currentRotation := currentTimeslot / common.ValidatorRotationPeriod

	// Guarantee must not be from future timeslot
	if guarantee.Timeslot > currentTimeslot {
		return errors.New("guarantee from future")
	}

	// If in same rotation or previous, valid
	if currentRotation-guaranteeRotation <= 1 {
		return nil
	}

	// Otherwise invalid (too old)
	return errors.New("report epoch before last")
}

// verifyGuaranteeCredentials verifies the credentials of a guarantee.
//
//	Equation 11.24 0.5.0
func verifyGuaranteeCredentials(
	guarantee block.Guarantee,
	validatorState validator.ValidatorState,
	entropyPool state.EntropyPool,
	currentTimeslot jamtime.Timeslot,
) (crypto.ED25519PublicKeySet, error) {
	reporters := make(crypto.ED25519PublicKeySet)

	validators, entropy, timeslotForPermutation := determineValidatorsAndDataForPermutation(
		guarantee.Timeslot,
		currentTimeslot,
		entropyPool,
		validatorState.CurrentValidators,
		validatorState.ArchivedValidators,
	)

	coreAssignments, err := PermuteAssignments(entropy, timeslotForPermutation)
	if err != nil {
		return reporters, fmt.Errorf("failed to compute core assignments: %w", err)
	}

	log.Printf("Core assignments for timeslot %d: %v", timeslotForPermutation, coreAssignments)

	// Generate work report hash
	reportBytes, err := jam.Marshal(guarantee.WorkReport)
	if err != nil {
		return reporters, fmt.Errorf("failed to marshal work report: %w", err)
	}
	hashed := crypto.HashData(reportBytes)
	message := append([]byte(state.SignatureContextGuarantee), hashed[:]...)

	for _, credential := range guarantee.Credentials {

		if !isValidatorAssignedToCore(credential.ValidatorIndex,
			guarantee.WorkReport.CoreIndex, coreAssignments) {
			log.Printf("Validator %d not assigned to core %d",
				credential.ValidatorIndex, guarantee.WorkReport.CoreIndex)
			return reporters, ErrWrongAssignment
		}

		if credential.ValidatorIndex >= uint16(len(validators)) {
			return reporters, fmt.Errorf("invalid validator index %d", credential.ValidatorIndex)
		}

		validatorKey := validators[credential.ValidatorIndex].Ed25519
		if len(validatorKey) != ed25519.PublicKeySize {
			return reporters, fmt.Errorf("invalid validator key size for validator %d", credential.ValidatorIndex)
		}

		// Verify signature
		sigValid := ed25519.Verify(validatorKey, message, credential.Signature[:])
		if !sigValid {
			log.Printf("Invalid signature from validator %d", credential.ValidatorIndex)
			log.Printf("  Key: %x", validatorKey)
			log.Printf("  Signature: %x", credential.Signature[:])
			return reporters, ErrBadSignature
		}

		reporters.Add(validatorKey)
	}

	return reporters, nil
}

// isValidatorAssignedToCore checks if a validator is assigned to a specific core.
func isValidatorAssignedToCore(validatorIndex uint16, coreIndex uint16, coreAssignments []uint32) bool {
	if int(validatorIndex) >= len(coreAssignments) {
		return false
	}

	assigned := coreAssignments[validatorIndex] == uint32(coreIndex)
	if !assigned {
		log.Printf("Validator %d assigned to core %d but tried to sign for core %d",
			validatorIndex, coreAssignments[validatorIndex], coreIndex)
		return false
	}
	return assigned
}

// RotateSequence rotates the sequence by n positions modulo C.
// Implements Equation (11.18 v.0.5.0): R(c, n) ≡ [(x + n) mod C ∣ x ∈ shuffledSequence]
func RotateSequence(sequence []uint32, n uint32) []uint32 {
	rotated := make([]uint32, len(sequence))
	for i, x := range sequence {
		rotated[i] = (x + n) % uint32(common.TotalNumberOfCores)
	}
	return rotated
}

// PermuteAssignments generates the core assignments for validators.
// Implements Equation (11.20 v0.6.2): P(e, t) ≡ R(F([⌊C ⋅ i/V⌋ ∣i ∈ NV], e), ⌊t mod E/R⌋)
func PermuteAssignments(entropy crypto.Hash, timeslot jamtime.Timeslot) ([]uint32, error) {
	// [⌊C ⋅ i/V⌋ ∣i ∈ NV]
	coreIndices := make([]uint32, common.NumberOfValidators)
	for i := uint32(0); i < common.NumberOfValidators; i++ {
		coreIndices[i] = (uint32(common.TotalNumberOfCores) * i) / common.NumberOfValidators
	}

	// F([⌊C ⋅ i/V⌋ ∣i ∈ NV], e)
	shuffledSequence, err := common.DeterministicShuffle(coreIndices, entropy)
	if err != nil {
		return nil, err
	}

	// ⌊(t mod E) / R⌋
	rotationAmount := uint32(timeslot % jamtime.TimeslotsPerEpoch / common.ValidatorRotationPeriod)

	// R(F([⌊C ⋅ i/V⌋ ∣i ∈ NV], e), ⌊(t mod E)/R⌋)
	rotatedSequence := RotateSequence(shuffledSequence, rotationAmount)

	return rotatedSequence, nil
}

// CalculateWorkReportsAndAccumulate implements equation 29: (ϑ′, ξ′, δ′, χ′, ι′, φ′, C) ≺ (W*, ϑ, ξ, δ†, χ, ι, φ)
// with the only difference that we take in available work reports and calculate the accumulatable WR
// eq. 4.16 W* ≺ (EA, ρ′) and
// eq. 4.17: (ϑ′, ξ′, δ‡, χ′, ι′, φ′, C) ≺ (W*, ϑ, ξ, δ, χ, ι, φ)
func CalculateWorkReportsAndAccumulate(header *block.Header, currentState *state.State, newTimeslot jamtime.Timeslot, workReports []block.WorkReport) (
	newAccumulationQueue state.AccumulationQueue,
	newAccumulationHistory state.AccumulationHistory,
	postAccumulationServiceState service.ServiceState,
	newPrivilegedServices service.PrivilegedServices,
	newValidatorKeys safrole.ValidatorsData,
	newPendingAuthorizersQueues state.PendingAuthorizersQueues,
	hashPairs ServiceHashPairs,
) {
	// W! ≡ [w S w <− W, |(w_x)p| = 0 ∧ wl = {}] (eq. 12.4)
	var immediatelyAccWorkReports []block.WorkReport
	var workReportWithDeps []state.WorkReportWithUnAccumulatedDependencies
	for _, workReport := range workReports {
		if len(workReport.RefinementContext.PrerequisiteWorkPackage) == 0 && len(workReport.SegmentRootLookup) == 0 {
			immediatelyAccWorkReports = append(immediatelyAccWorkReports, workReport)
		} else if len(workReport.RefinementContext.PrerequisiteWorkPackage) > 0 || len(workReport.SegmentRootLookup) != 0 {
			// |(w_x)p| > 0 ∨ wl ≠ {} (part of eq. 12.5)
			workReportWithDeps = append(workReportWithDeps, getWorkReportDependencies(workReport))
		}
	}

	// WQ ≡ E([D(w) | w <− W, |(w_x)p| > 0 ∨ wl ≠ {}], {ξ) (eq. 12.5)
	var queuedWorkReports = updateQueue(workReportWithDeps, flattenAccumulationHistory(currentState.AccumulationHistory))

	// let m = Ht mod E
	timeslotPerEpoch := header.TimeSlotIndex % jamtime.TimeslotsPerEpoch

	// q = E(⋃(ϑm...) ⌢ ⋃(ϑ...m) ⌢ WQ, P(W!)) (eq. 12.12)
	workReportsFromQueueDeps := updateQueue(
		slices.Concat(
			slices.Concat(currentState.AccumulationQueue[timeslotPerEpoch:]...), // ⋃(ϑm...)
			slices.Concat(currentState.AccumulationQueue[:timeslotPerEpoch]...), // ⋃(ϑ...m)
			queuedWorkReports, // WQ
		),
		getWorkPackageHashes(immediatelyAccWorkReports), // P(W!)
	)
	// W* ≡ W! ⌢ Q(q) (eq. 12.11)
	var accumulatableWorkReports = slices.Concat(immediatelyAccWorkReports, accumulationPriority(workReportsFromQueueDeps))

	privSvcGas := uint64(0)
	for _, gas := range currentState.PrivilegedServices.AmountOfGasPerServiceId {
		privSvcGas += gas
	}
	// let g = max(GT, GA ⋅ C + [∑ x∈V(χ_g)](x)) (eq. 12.20)
	gasLimit := max(service.TotalGasAccumulation, common.MaxAllocatedGasAccumulation*uint64(common.TotalNumberOfCores)+privSvcGas)

	// let (n, o, t, C) = ∆+(g, W∗, (χ, δ, ι, φ), χg) (eq. 12.21)
	maxReports, newAccumulationState, transfers, hashPairs := NewAccumulator(currentState, header, newTimeslot).
		SequentialDelta(gasLimit, accumulatableWorkReports, state.AccumulationState{
			PrivilegedServices:       currentState.PrivilegedServices,
			ServiceState:             currentState.Services,
			ValidatorKeys:            currentState.ValidatorState.QueuedValidators,
			PendingAuthorizersQueues: currentState.PendingAuthorizersQueues,
		}, currentState.PrivilegedServices)

	// (χ′, δ†, ι′, φ′) ≡ o (eq. 12.22)
	intermediateServiceState := newAccumulationState.ServiceState
	newPrivilegedServices = newAccumulationState.PrivilegedServices
	newValidatorKeys = newAccumulationState.ValidatorKeys
	newPendingAuthorizersQueues = newAccumulationState.PendingAuthorizersQueues

	// δ‡ = {s ↦ ΨT (δ†, τ ′, s, R(t, s)) S (s ↦ a) ∈ δ†} (eq. 12.24)
	postAccumulationServiceState = make(service.ServiceState)
	for serviceId := range intermediateServiceState {
		newService := InvokePVMOnTransfer(
			intermediateServiceState,
			serviceId,
			transfersForReceiver(transfers, serviceId),
		)
		postAccumulationServiceState[serviceId] = newService
	}

	// ξ′E−1 = P(W*...n) (eq. 12.25)
	// ∀i ∈ NE−1 ∶ ξ′i ≡ ξi+1 (eq. 12.26)
	newAccumulationHistory = state.AccumulationHistory(append(
		currentState.AccumulationHistory[1:],
		getWorkPackageHashes(accumulatableWorkReports[:maxReports]),
	))

	// ξ′E−1
	lastAccumulation := newAccumulationHistory[jamtime.TimeslotsPerEpoch-1]

	// ∀i ∈ N_E (eq. 12.27)
	for i := range jamtime.TimeslotsPerEpoch {
		indexPerEpoch := mod(int(timeslotPerEpoch)-i, jamtime.TimeslotsPerEpoch)
		if i == 0 { // if i = 0
			// ϑ′↺m−i ≡ E(WQ, ξ′E−1)
			newAccumulationQueue[indexPerEpoch] = updateQueue(queuedWorkReports, lastAccumulation)
		} else if 1 <= i && jamtime.Timeslot(i) < newTimeslot-currentState.TimeslotIndex { // if 1 ≤ i < τ′ − τ
			// ϑ′↺m−i ≡ []
			newAccumulationQueue[indexPerEpoch] = nil
		} else if jamtime.Timeslot(i) >= newTimeslot-currentState.TimeslotIndex { // if i ≥ τ′ − τ
			// ϑ′↺m−i ≡ E(ϑ↺m−i, ξ′E−1)
			newAccumulationQueue[indexPerEpoch] = updateQueue(currentState.AccumulationQueue[indexPerEpoch], lastAccumulation)
		}
	}

	return
}

// accumulationPriority Q(r ⟦(W, {H})⟧) → ⟦W⟧ (eq. 12.8)
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

// getWorkReportDependencies D(w) ≡ (w, {(wx)p} ∪ K(wl)) (eq. 12.6)
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

// flattenAccumulationHistory {ξ ≡ x∈ξ ⋃(x) (eq. 12.2)
func flattenAccumulationHistory(accHistory state.AccumulationHistory) (hashes map[crypto.Hash]struct{}) {
	hashes = make(map[crypto.Hash]struct{})
	for _, epochHistory := range accHistory {
		maps.Copy(hashes, epochHistory)
	}
	return hashes
}

// updateQueue E(r ⟦(W, {H})⟧, x {H}) → ⟦(W, {H})⟧ (eq. 12.7)
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

// P(w {W}) → {H} (eq. 12.9)
func getWorkPackageHashes(workReports []block.WorkReport) (hashes map[crypto.Hash]struct{}) {
	hashes = make(map[crypto.Hash]struct{})
	// {(ws)h S w ∈ w}
	for _, workReport := range workReports {
		hashes[workReport.WorkPackageSpecification.WorkPackageHash] = struct{}{}
	}
	return hashes
}

// transfersForReceiver R(t ⟦T⟧, d NS ) → ⟦T⟧ (eq. 12.23)
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

// verifyAvailability (129) implements availability verification part of equations 29-30:
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
		CoreAssignments:   ctx.AccumulationState.PendingAuthorizersQueues,
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

// assuranceIsOrderedByValidatorIndex (126) ∀i ∈ {1 ... |E_A|} ∶ EA[i − 1]v < EA[i]v
func assuranceIsOrderedByValidatorIndex(assurances block.AssurancesExtrinsic) bool {
	return slices.IsSortedFunc(assurances, func(a, b block.Assurance) int {
		if a.ValidatorIndex < b.ValidatorIndex {
			return -1
		} else if a.ValidatorIndex > b.ValidatorIndex {
			return 1
		}
		return 0
	})
}

func CalculateIntermediateCoreFromAssurances(validators safrole.ValidatorsData, assignments state.CoreAssignments, header block.Header, assurances block.AssurancesExtrinsic) (state.CoreAssignments, []*block.WorkReport, error) {
	if err := validateAssurancesSignature(validators, header, assurances); err != nil {
		return assignments, nil, err
	}

	if !assuranceIsOrderedByValidatorIndex(assurances) {
		return assignments, nil, ErrBadOrder
	}

	return CalculateIntermediateCoreAssignmentsFromAvailability(assurances, assignments, header)
}

// validateAssurancesSignature (127) ∀a ∈ EA ∶ as ∈ Eκ′[av ]e ⟨XA ⌢ H(E(Hp, af ))⟩
func validateAssurancesSignature(validators safrole.ValidatorsData, header block.Header, assurances block.AssurancesExtrinsic) error {
	for _, assurance := range assurances {
		if int(assurance.ValidatorIndex) >= common.NumberOfValidators || validators[assurance.ValidatorIndex] == nil {
			return ErrBadValidatorIndex
		}
		// ∀a ∈ EA ∶ a_a = Hp (eq. 11.11)
		if assurance.Anchor != header.ParentHash {
			return ErrBadAttestationParent
		}
		var message []byte
		b, err := jam.Marshal(header.ParentHash)
		if err != nil {
			return fmt.Errorf("error encoding header parent hash %w", err)
		}
		message = append(message, b...)
		b, err = jam.Marshal(assurance.Bitfield)
		if err != nil {
			return fmt.Errorf("error encoding assurance bitfield %w", err)
		}
		message = append(message, b...)
		messageHash := crypto.HashData(message)
		if !ed25519.Verify(validators[assurance.ValidatorIndex].Ed25519, append([]byte(state.SignatureContextAvailable), messageHash[:]...), assurance.Signature[:]) {
			return ErrBadSignature
		}
	}
	return nil
}

// W ≡ [ ρ†[c]w | c <− N_C, ∑ [a∈E_A] a_f [c] > 2/3 V ]
func GetAvailableWorkReports(coreAssignments state.CoreAssignments) (workReports []block.WorkReport) {
	for _, c := range coreAssignments {
		if c != nil {
			workReports = append(workReports, *c.WorkReport)
		}
	}
	return workReports
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
	if totalMinGas >= common.MaxAllocatedGasAccumulation {
		return allocations
	}
	remainingGas := common.MaxAllocatedGasAccumulation - totalMinGas

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

// CalculateNewValidatorStatistics implements equation 30:
// π′ ≺ (EG, EP, EA, ET, τ, κ′, π, H)
func CalculateNewValidatorStatistics(block block.Block, timeslot jamtime.Timeslot, validatorStatistics validator.ValidatorStatisticsState, reporters crypto.ED25519PublicKeySet, currValidators safrole.ValidatorsData) validator.ValidatorStatisticsState {
	newStats := validatorStatistics

	// Implements equations 170-171:
	// let e = ⌊τ/E⌋, e′ = ⌊τ′/E⌋
	// (a, π′₁) ≡ { (π₀, π₁) if e′ = e
	//              ([{0,...,[0,...]},...], π₀) otherwise
	if timeslot.ToEpoch() != block.Header.TimeSlotIndex.ToEpoch() {
		// Rotate statistics - completed stats become history, start fresh present stats
		newStats[0] = newStats[1]                                                // Move current to history
		newStats[1] = [common.NumberOfValidators]validator.ValidatorStatistics{} // Reset current
	}

	// Implements equation 172: ∀v ∈ NV
	for v := uint16(0); v < uint16(len(newStats[0])); v++ {
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
		// Where R is the set of reporter keys defined in 11.26 0.6.2
		for reporter := range reporters {
			if currValidators[v] != nil && slices.Equal(currValidators[v].Ed25519, reporter[:]) {
				newStats[1][v].NumOfGuaranteedReports++
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

// ServiceHashPairs B ≡ {(NS , H)} (eq. 12.15)
type ServiceHashPairs []ServiceHashPair

type ServiceHashPair struct {
	ServiceId block.ServiceId
	Hash      crypto.Hash
}

// SequentialDelta implements equation 12.16 (∆+)
func (a *Accumulator) SequentialDelta(
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
	gasUsed, newCtx, transfers, hashPairs := a.ParallelDelta(
		ctx,
		workReports[:maxReports],
		privileged.AmountOfGasPerServiceId,
	)

	// If we have remaining reports and gas, process recursively (∆+)
	if maxReports < len(workReports) {
		remainingGas := gasLimit - gasUsed
		if remainingGas > 0 {
			moreItems, finalCtx, moreTransfers, moreHashPairs := a.SequentialDelta(
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

func getServiceIdsAsSet(m map[block.ServiceId]service.ServiceAccount) map[block.ServiceId]struct{} {
	m2 := make(map[block.ServiceId]struct{}, len(m))
	for k := range m {
		m2[k] = struct{}{}
	}
	return m2
}

// ParallelDelta implements equation 12.17 (∆*)
func (a *Accumulator) ParallelDelta(
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
	// s = {rs | w ∈ w, r ∈ wr} ∪ K(f)
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

	// n = ⋃[s∈s]({(∆1(o, w, f , s)o)d ∖ K(d ∖ {s})})
	allResultServices := make(map[block.ServiceId]service.ServiceAccount)

	// m = ⋃[s∈s](K(d) ∖ K((∆1(o, w, f , s)o)d))
	resultServicesExclude := make(map[block.ServiceId]struct{})

	for svcId := range serviceIndices {
		wg.Add(1)
		go func(serviceId block.ServiceId) {
			defer wg.Done()

			// Process single service using Delta1
			accState, deferredTransfers, resultHash, gasUsed := a.Delta1(initialAccState, workReports, privilegedGas, serviceId)
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

			resultServices := maps.Clone(accState.ServiceState)

			// (∆1(o, w, f , s)o)d ∖ K(d ∖ {s})
			maps.DeleteFunc(resultServices, func(id block.ServiceId, _ service.ServiceAccount) bool {
				if id == serviceId {
					return false
				}

				_, ok := initialAccState.ServiceState[id]
				return ok
			})

			maps.Copy(allResultServices, resultServices)

			initialServicesKeys := getServiceIdsAsSet(initialAccState.ServiceState)
			maps.DeleteFunc(initialServicesKeys, func(id block.ServiceId, _ struct{}) bool {
				_, ok := accState.ServiceState[id]
				return ok
			})

			maps.Copy(resultServicesExclude, initialServicesKeys)

		}(svcId)
	}

	wg.Add(1)
	go func(serviceId block.ServiceId) {
		defer wg.Done()

		// Process single service using Delta1
		accState, _, _, _ := a.Delta1(initialAccState, workReports, privilegedGas, serviceId)
		mu.Lock()
		defer mu.Unlock()

		newAccState.PrivilegedServices = accState.PrivilegedServices

	}(initialAccState.PrivilegedServices.ManagerServiceId)

	wg.Add(1)
	go func(serviceId block.ServiceId) {
		defer wg.Done()

		// Process single service using Delta1
		accState, _, _, _ := a.Delta1(initialAccState, workReports, privilegedGas, serviceId)
		mu.Lock()
		defer mu.Unlock()

		newAccState.ValidatorKeys = accState.ValidatorKeys

	}(initialAccState.PrivilegedServices.AssignServiceId)

	wg.Add(1)
	go func(serviceId block.ServiceId) {
		defer wg.Done()

		// Process single service using Delta1
		accState, _, _, _ := a.Delta1(initialAccState, workReports, privilegedGas, serviceId)
		mu.Lock()
		defer mu.Unlock()

		newAccState.PendingAuthorizersQueues = accState.PendingAuthorizersQueues

	}(initialAccState.PrivilegedServices.DesignateServiceId)

	// Wait for all goroutines to complete
	wg.Wait()

	// (d ∪ n) ∖ m
	maps.Copy(newAccState.ServiceState, initialAccState.ServiceState)
	maps.Copy(newAccState.ServiceState, allResultServices)
	maps.DeleteFunc(newAccState.ServiceState, func(id block.ServiceId, _ service.ServiceAccount) bool {
		_, ok := resultServicesExclude[id]
		return ok
	})

	// Sort accumulation pairs by service ID to ensure deterministic output
	sort.Slice(accumHashPairs, func(i, j int) bool {
		return accumHashPairs[i].ServiceId < accumHashPairs[j].ServiceId
	})

	return totalGasUsed, newAccState, allTransfers, accumHashPairs
}

// Delta1 implements equation 12.19 ∆1 (U, ⟦W⟧, D⟨NS → NG⟩, NS ) → (U, ⟦T⟧, H?, NG)
func (a *Accumulator) Delta1(
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

	// InvokePVM VM for accumulation (ΨA)
	return a.InvokePVM(accumulationState, a.newTimeslot, serviceIndex, gasLimit, operands)
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
