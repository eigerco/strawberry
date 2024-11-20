package statetransition

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"
	"log"
	"maps"
	"reflect"
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
	"github.com/eigerco/strawberry/internal/validator"
	"github.com/eigerco/strawberry/pkg/serialization/codec/jam"
)

const (
	signatureContextGuarantee = "$jam_guarantee"  // X_G ≡ $jam_guarantee (141 v0.4.5)
	signatureContextAvailable = "$jam_available " // X_A ≡ $jam_available (128 v0.4.5)
)

// UpdateState updates the state
// TODO: all the calculations which are not dependent on intermediate / new state can be done in parallel
//
//	it might be worth making State immutable and make it so that UpdateState returns a new State with all the updated fields
func UpdateState(s *state.State, newBlock block.Block) error {
	if newBlock.Header.TimeSlotIndex.IsInFuture() {
		return errors.New("invalid block, it is in the future")
	}

	if !assuranceIsAnchoredOnParent(newBlock.Header, newBlock.Extrinsic.EA) {
		return errors.New("invalid block, the assurance is not anchored on parent")
	}
	if !assuranceIsOrderedByValidatorIndex(newBlock.Extrinsic.EA) {
		return errors.New("invalid block, the assurance is not ordered by validator index")
	}

	if err := validateExtrinsicGuarantees(newBlock.Header, s, newBlock.Extrinsic.EG, block.AncestorStoreSingleton); err != nil {
		return fmt.Errorf("extrinsic guarantees validation failed, err: %w", err)
	}

	newTimeState := calculateNewTimeState(newBlock.Header)

	// Update SAFROLE state.
	safroleInput, err := NewSafroleInputFromBlock(newBlock)
	if err != nil {
		return err
	}
	newEntropyPool, newValidatorState, _, err := UpdateSafroleState(safroleInput, s.TimeslotIndex, s.EntropyPool, s.ValidatorState)
	if err != nil {
		return err
	}

	newValidatorStatistics := calculateNewValidatorStatistics(newBlock, newTimeState, s.ValidatorStatistics)

	intermediateCoreAssignments := calculateIntermediateCoreAssignmentsFromExtrinsics(newBlock.Extrinsic.ED, s.CoreAssignments)
	intermediateCoreAssignments = calculateIntermediateCoreAssignmentsFromAvailability(newBlock.Extrinsic.EA, intermediateCoreAssignments)

	newCoreAssignments := calculateNewCoreAssignments(newBlock.Extrinsic.EG, intermediateCoreAssignments, s.ValidatorState, newTimeState, newEntropyPool)

	intermediateServiceState := calculateIntermediateServiceState(newBlock.Extrinsic.EP, s.Services, newTimeState)

	workReports := getAvailableWorkReports(newBlock.Extrinsic.EA, newCoreAssignments)

	newAccumulationQueue,
		newAccumulationHistory,
		newServices,
		newPrivilegedServices,
		newQueuedValidators,
		newPendingCoreAuthorizations,
		serviceHashPairs := calculateWorkReportsAndAccumulate(&newBlock.Header, s,
		newTimeState,
		workReports,
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
		return err
	}

	newJudgements := calculateNewJudgements(newBlock.Extrinsic.ED, s.PastJudgements)

	newCoreAuthorizations := calculateNewCoreAuthorizations(newBlock.Header, newBlock.Extrinsic.EG, newPendingCoreAuthorizations, s.CoreAuthorizersPool)

	if assurancesSignatureIsInvalid(newValidatorState.CurrentValidators, newBlock.Header, newBlock.Extrinsic.EA) {
		log.Printf("extrinsic assurance signature is invalid")
		return err
	}

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
	s.Services = newServices
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
	accumulationRoot, err := computeAccumulationRoot(serviceHashPairs)
	if err != nil {
		return nil, err
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

	// Equation 83: p = {((g_w)_s)_h ↦ ((g_w)_s)_e | g ∈ E_G}
	workPackageMapping := buildWorkPackageMapping(guarantees.Guarantees)

	// Equation 83: let n = {p, h ▸▸ H(H), b, s ▸▸ H_0}
	headerBytes, err := jam.Marshal(header)
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
		// Equation 74: r ∈ NN implies entry index must be 0 or 1 (v.0.4.5)
		if tp.EntryIndex > 1 {
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
			err := newValidatorState.SafroleState.SealingKeySeries.SetValue(safrole.TicketsBodies(sealingTickets))
			if err != nil {
				return entropyPool, validatorState, SafroleOutput{}, err
			}
		} else {
			// Use bandersnatch keys for sealing keys.
			fallbackKeys, err := safrole.SelectFallbackKeys(newEntropyPool[2], newValidatorState.CurrentValidators)
			if err != nil {
				return entropyPool, validatorState, SafroleOutput{}, err
			}
			err = newValidatorState.SafroleState.SealingKeySeries.SetValue(fallbackKeys)
			if err != nil {
				return entropyPool, validatorState, SafroleOutput{}, err
			}
		}

		// Compute epoch marker (H_e).
		// Equation 72: He ≡ (η′1, [kb S k <− γ′k]) if e′ > e (v.0.4.5)
		output.EpochMark = &block.EpochMarker{
			Entropy: newEntropyPool[1],
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
		newEntropyPool = state.RotateEntropyPool(entropyPool)
	}

	newEntropyPool[0] = crypto.HashData(append(entropyPool[0][:], entropyInput[:]...))
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
	entropyPool state.EntropyPool,
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

			if verifyGuaranteeCredentials(guarantee, validators, entropyPool, newTimeslot) {
				newAssignments[coreIndex] = state.Assignment{
					WorkReport: &guarantee.WorkReport,
					Time:       newTimeslot,
				}
			}
		}
	}

	return newAssignments
}

func validateExtrinsicGuarantees(header block.Header, currentState *state.State, guarantees block.GuaranteesExtrinsic, ancestorStore *block.AncestorStore) error {

	// let x ≡ {w_x S w ∈ w} , p ≡ {(w_s)h S w ∈ w} (145 v0.4.5)
	contexts := make(map[block.RefinementContext]struct{})
	extrinsicWorkPackages := make(map[crypto.Hash]crypto.Hash)

	prerequisitePackageHashes := make(map[crypto.Hash]struct{})

	// [⋃ x∈β] K(xp)
	recentBlockPrerequisites := make(map[crypto.Hash]crypto.Hash)

	// [⋃ x∈β] K(x_p) ∪ [⋃ x∈ξ] x ∪ q ∪ a
	pastWorkPackages := make(map[crypto.Hash]struct{})
	for _, recentBlock := range currentState.RecentBlocks {
		for key, val := range recentBlock.WorkReportHashes {
			recentBlockPrerequisites[key] = val
			pastWorkPackages[key] = struct{}{}
		}
	}

	for _, guarantee := range guarantees.Guarantees {
		contexts[guarantee.WorkReport.RefinementContext] = struct{}{}
		extrinsicWorkPackages[guarantee.WorkReport.WorkPackageSpecification.WorkPackageHash] = guarantee.WorkReport.WorkPackageSpecification.SegmentRoot
		// ∀w ∈ w ∶ [∑ r∈wr] (rg) ≤ GA ∧ ∀r ∈ wr ∶ rg ≥ δ[rs]g (eq. 144 v0.4.5)
		totalGas := uint64(0)
		for _, r := range guarantee.WorkReport.WorkResults {
			if r.GasPrioritizationRatio < currentState.Services[r.ServiceId].GasLimitForAccumulator {
				return fmt.Errorf("work-report allotted accumulation gas for service is too small")
			}
			totalGas += r.GasPrioritizationRatio
		}
		if totalGas > service.CoreGasAccumulation {
			return fmt.Errorf("work-reports total allotted accumulation gas is greater than the gas limit GA")
		}

		for key := range guarantee.WorkReport.SegmentRootLookup {
			prerequisitePackageHashes[key] = struct{}{}
		}
		if guarantee.WorkReport.RefinementContext.PrerequisiteWorkPackage != nil {
			prerequisitePackageHashes[*guarantee.WorkReport.RefinementContext.PrerequisiteWorkPackage] = struct{}{}

			// let q = {(wx)p S q ∈ ϑ, w ∈ K(q)} (150 v0.4.5)
			for _, workReportsAndDeps := range currentState.AccumulationQueue {
				for _, wd := range workReportsAndDeps {
					if reflect.DeepEqual(wd.WorkReport, guarantee.WorkReport) { // TODO maybe use hash compare instead of reflect
						pastWorkPackages[*guarantee.WorkReport.RefinementContext.PrerequisiteWorkPackage] = struct{}{}
					}
				}
			}
		}

		// let a = {((iw )x)p S i ∈ ρ, i ≠ ∅} (151 v0.4.5)
		for _, ca := range currentState.CoreAssignments {
			if ca.WorkReport != nil && ca.WorkReport.RefinementContext.PrerequisiteWorkPackage != nil {
				pastWorkPackages[*ca.WorkReport.RefinementContext.PrerequisiteWorkPackage] = struct{}{}
			}
		}
	}

	// |p| = |w| (146 v0.4.5)
	if len(extrinsicWorkPackages) != len(guarantees.Guarantees) {
		return fmt.Errorf("cardinality of work-package hashes is not equal to the length of work-reports")
	}

	for context := range contexts {
		// ∀x ∈ x ∶ ∃y ∈ β ∶ x_a = y_h ∧ x_s = ys ∧ xb = HK (EM (yb)) (147 v0.4.5)
		if !anchorBlockInRecentBlocks(context, currentState) {
			return fmt.Errorf("anchor block not present within recent blocks")
		}

		// ∀x ∈ x ∶ xt ≥ Ht − L (148 v0.4.5)
		if context.LookupAnchor.Timeslot < header.TimeSlotIndex-state.MaxTimeslotsForPreimage {
			return fmt.Errorf("lookup anchor block not withing the last %d timeslots", state.MaxTimeslotsForPreimage)
		}

		// ∀x ∈ x ∶ ∃h ∈ A ∶ ht = xt ∧ H(h) = xl (149 v0.4.5)
		_, err := ancestorStore.FindAncestor(func(ancestor block.Header) bool {
			encodedHeader, err := jam.Marshal(ancestor)
			if err != nil {
				return false
			}
			if ancestor.TimeSlotIndex == context.LookupAnchor.Timeslot && crypto.HashData(encodedHeader) == context.LookupAnchor.HeaderHash {
				return true
			}
			return false
		})
		if err != nil {
			return fmt.Errorf("no record of header found: %w", err)
		}
	}

	accHistoryPrerequisites := make(map[crypto.Hash]struct{})
	for _, hashSet := range currentState.AccumulationHistory {
		maps.Copy(accHistoryPrerequisites, hashSet)
	}

	// ∀p ∈ p, p ∉ [⋃ x∈β] K(x_p) ∪ [⋃ x∈ξ] x ∪ q ∪ a (152 v0.4.5)
	for p := range extrinsicWorkPackages {
		if _, ok := pastWorkPackages[p]; ok {
			return fmt.Errorf("report work-package is the work-package of some other report made in the past")
		}
	}

	// p ∪ {x | x ∈ b_p, b ∈ β} (153,154 v0.4.5)
	extrinsicAndRecentWorkPackages := maps.Clone(extrinsicWorkPackages)
	maps.Copy(extrinsicAndRecentWorkPackages, recentBlockPrerequisites)

	// ∀w ∈ w, ∀p ∈ (wx)p ∪ K(wl) ∶ p ∈ p ∪ {x S x ∈ K(bp), b ∈ β} (153 v0.4.5)
	for p := range prerequisitePackageHashes {
		if _, ok := extrinsicWorkPackages[p]; !ok {
			return fmt.Errorf("prerequisite report work-package is neither in the extrinsic nor in recent history")
		}
	}

	for _, guarantee := range guarantees.Guarantees {
		// ∀w ∈ w ∶ wl ⊆ p ∪ [⋃ b∈β] b_p (155 v0.4.5)
		for lookupKey, lookupValue := range guarantee.WorkReport.SegmentRootLookup {
			if extrinsicAndRecentWorkPackages[lookupKey] != lookupValue {
				return fmt.Errorf("segment root not present in the present nor recent blocks")
			}
		}

		// ∀w ∈ w, ∀r ∈ wr ∶ rc = δ[rs]c (156 v0.4.5)
		for _, workResult := range guarantee.WorkReport.WorkResults {
			if workResult.ServiceHashCode != currentState.Services[workResult.ServiceId].CodeHash {
				return fmt.Errorf("work result code does not correspond with the service code")
			}
		}
	}
	return nil
}

// anchorBlockInRecentBlocks ∀x ∈ x ∶ ∃y ∈ β ∶ x_a = y_h ∧ x_s = ys ∧ xb = HK (EM (yb)) (147 v0.4.5)
func anchorBlockInRecentBlocks(context block.RefinementContext, currentState *state.State) bool {
	for _, y := range currentState.RecentBlocks {
		encodedMMR, err := jam.Marshal(y.AccumulationResultMMR)
		if err != nil {
			return false
		}

		if context.Anchor.HeaderHash == y.HeaderHash && context.Anchor.PosteriorStateRoot == y.StateRoot && context.Anchor.PosteriorBeefyRoot != crypto.KeccakData(encodedMMR) {
			return true
		}
	}
	return false
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
func verifyGuaranteeCredentials(
	guarantee block.Guarantee,
	validators safrole.ValidatorsData,
	entropyPool state.EntropyPool,
	currentTimeslot jamtime.Timeslot,
) bool {
	// Verify that credentials are ordered by validator index (equation 138)
	for i := 1; i < len(guarantee.Credentials); i++ {
		if guarantee.Credentials[i-1].ValidatorIndex >= guarantee.Credentials[i].ValidatorIndex {
			return false
		}
	}

	// Determine which assignments to use based on timeslots
	guaranteeRotation := guarantee.Timeslot / common.ValidatorRotationPeriod
	currentRotation := currentTimeslot / common.ValidatorRotationPeriod

	var coreAssignments []uint32
	var err error

	if guaranteeRotation == currentRotation {
		// Use G assignments with η₂
		coreAssignments, err = PermuteAssignments(entropyPool[2], guarantee.Timeslot)
	} else {
		// Use G* assignments with η₃
		adjustedTimeslot := guarantee.Timeslot - common.ValidatorRotationPeriod
		coreAssignments, err = PermuteAssignments(entropyPool[3], adjustedTimeslot)
	}

	if err != nil {
		return false
	}

	// Verify the signatures using the correct validator keys (Equation 140 v0.4.5)
	for _, credential := range guarantee.Credentials {
		if credential.ValidatorIndex >= uint16(len(validators)) {
			return false
		}

		validatorKey := validators[credential.ValidatorIndex]
		// Check if the validator key is valid
		if len(validatorKey.Ed25519) != ed25519.PublicKeySize {
			return false
		}

		// Check if the validator is assigned to the core specified in the work report
		if !isValidatorAssignedToCore(credential.ValidatorIndex, guarantee.WorkReport.CoreIndex, coreAssignments) {
			return false
		}

		reportBytes, err := jam.Marshal(guarantee.WorkReport)
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

// isValidatorAssignedToCore checks if a validator is assigned to a specific core.
func isValidatorAssignedToCore(validatorIndex uint16, coreIndex uint16, coreAssignments []uint32) bool {
	if int(validatorIndex) >= len(coreAssignments) {
		return false
	}

	return coreAssignments[validatorIndex] == uint32(coreIndex)
}

// RotateSequence rotates the sequence by n positions modulo C.
// Implements Equation (133 v.0.4.5): R(c, n) ≡ [(x + n) mod C ∣ x ∈ shuffledSequence]
func RotateSequence(sequence []uint32, n uint32) []uint32 {
	rotated := make([]uint32, len(sequence))
	for i, x := range sequence {
		rotated[i] = (x + n) % uint32(common.TotalNumberOfCores)
	}
	return rotated
}

// PermuteAssignments generates the core assignments for validators.
// Implements Equation (134 v0.4.5): P(e, t) ≡ R(F([⌊C ⋅ i/V⌋ ∣i ∈ NV], e), ⌊t mod E/R⌋)
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
	timeslotModEpoch := timeslot % jamtime.TimeslotsPerEpoch
	rotationAmount := uint32(timeslotModEpoch / common.ValidatorRotationPeriod)

	// R(F([⌊C ⋅ i/V⌋ ∣i ∈ NV], e), ⌊t mod E/R⌋)
	rotatedSequence := RotateSequence(shuffledSequence, rotationAmount)

	return rotatedSequence, nil
}

// calculateWorkReportsAndAccumulate implements equation 29: (ϑ′, ξ′, δ′, χ′, ι′, φ′, C) ≺ (W*, ϑ, ξ, δ†, χ, ι, φ)
// with the only difference that we take in available work reports and calculate the accumulatable WR
func calculateWorkReportsAndAccumulate(
	header *block.Header,
	currentState *state.State,
	newTimeslot jamtime.Timeslot,
	workReports []block.WorkReport,
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
	// (165) W! ≡ [w S w <− W, (wx)p = ∅ ∧ wl = {}]
	var immediatelyAccWorkReports []block.WorkReport
	var workReportWithDeps []state.WorkReportWithUnAccumulatedDependencies
	for _, workReport := range workReports {
		if workReport.RefinementContext.PrerequisiteWorkPackage == nil && len(workReport.SegmentRootLookup) == 0 {
			immediatelyAccWorkReports = append(immediatelyAccWorkReports, workReport)
			continue
		}
		// if (wx)p ≠ ∅ ∨ wl ≠ {}
		workReportWithDeps = append(workReportWithDeps, getWorkReportDependencies(workReport))
	}

	// (166) WQ ≡ E([D(w) S w <− W, (wx)p ≠ ∅ ∨ wl ≠ {}], {ξ)
	var queuedWorkReports = updateQueue(workReportWithDeps, flattenAccumulationHistory(accHistory))

	// let m = Ht mod E
	timeslotPerEpoch := header.TimeSlotIndex % jamtime.TimeslotsPerEpoch

	// (173) q = E(⋃(ϑm...) ⌢ ⋃(ϑ...m) ⌢ WQ, P(W!))
	workReportsFromQueueDeps := updateQueue(
		slices.Concat(
			slices.Concat(accQueue[timeslotPerEpoch:]...), // ⋃(ϑm...)
			slices.Concat(accQueue[:timeslotPerEpoch]...), // ⋃(ϑ...m)
			queuedWorkReports, // WQ
		),
		getWorkPackageHashes(immediatelyAccWorkReports), // P(W!)
	)
	// (172) W* ≡ W! ⌢ Q(q)
	var accumulatableWorkReports = slices.Concat(immediatelyAccWorkReports, accumulationPriority(workReportsFromQueueDeps))

	privSvcGas := uint64(0)
	for _, gas := range privilegedServices.AmountOfGasPerServiceId {
		privSvcGas += gas
	}
	// (181) let g = max(GT, GA ⋅ C + [∑ x∈V(χ_g)](x))
	gasLimit := max(service.TotalGasAccumulation, service.CoreGasAccumulation*uint64(common.TotalNumberOfCores)+privSvcGas)

	// (182) let (n, o, t, C) = ∆+(g, W∗, (χ, δ†, ι, φ), χg )
	maxReports, newAccumulationState, transfers, hashPairs := NewAccumulator(currentState, header).SequentialDelta(gasLimit, accumulatableWorkReports, state.AccumulationState{
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
		newService := InvokePVMOnTransfer(
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
		} else if 1 <= i && jamtime.Timeslot(i) < newTimeslot-currentState.TimeslotIndex { // if 1 ≤ i < τ ′ − τ
			// ϑ′↺m−i ≡ []
			newAccumulationQueue[indexPerEpoch] = []state.WorkReportWithUnAccumulatedDependencies{}
		} else if jamtime.Timeslot(i) >= newTimeslot-currentState.TimeslotIndex { // if i ≥ τ ′ − τ
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

// accumulationPriority (169) Q(r ⟦(W, {H})⟧) → ⟦W⟧
func accumulationPriority(workReportAndDeps []state.WorkReportWithUnAccumulatedDependencies) []block.WorkReport {
	var workReports []block.WorkReport
	for _, wd := range workReportAndDeps {
		workReports = append(workReports, wd.WorkReport)
	}

	if len(workReports) == 0 {
		return []block.WorkReport{}
	}

	return accumulationPriority(updateQueue(workReportAndDeps, getWorkPackageHashes(workReports)))
}

// getWorkReportDependencies (167) D(w) ≡ (w, {(wx)p} ∪ K(wl))
func getWorkReportDependencies(workReport block.WorkReport) state.WorkReportWithUnAccumulatedDependencies {
	deps := make(map[crypto.Hash]struct{})
	if workReport.RefinementContext.PrerequisiteWorkPackage != nil {
		deps[*workReport.RefinementContext.PrerequisiteWorkPackage] = struct{}{}
	}
	for key := range workReport.SegmentRootLookup {
		deps[key] = struct{}{}
	}
	return state.WorkReportWithUnAccumulatedDependencies{
		WorkReport:   workReport,
		Dependencies: deps,
	}
}

// flattenAccumulationHistory (163) {ξ ≡ x∈ξ ⋃(x)
func flattenAccumulationHistory(accHistory state.AccumulationHistory) (hashes map[crypto.Hash]struct{}) {
	hashes = make(map[crypto.Hash]struct{})
	for _, epochHistory := range accHistory {
		maps.Copy(hashes, epochHistory)
	}
	return hashes
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

// assuranceIsAnchoredOnParent (125) ∀a ∈ EA ∶ a_a = Hp
func assuranceIsAnchoredOnParent(header block.Header, assurances block.AssurancesExtrinsic) bool {
	for _, assurance := range assurances {
		if assurance.Anchor != header.ParentHash {
			return false
		}
	}
	return true
}

// assuranceIsOrderedByValidatorIndex (126) ∀i ∈ {1 . . . SEAS} ∶ EA[i − 1]v < EA[i]v
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

// assurancesSignatureIsInvalid (127) ∀a ∈ EA ∶ as ∈ Eκ′[av ]e ⟨XA ⌢ H(E(Hp, af ))⟩
func assurancesSignatureIsInvalid(validators safrole.ValidatorsData, header block.Header, assurances block.AssurancesExtrinsic) bool {
	for _, assurance := range assurances {
		var message []byte
		b, err := jam.Marshal(header.ParentHash)
		if err != nil {
			log.Println("error encoding header parent hash", err)
			return false
		}
		message = append(message, b...)
		b, err = jam.Marshal(assurance.Bitfield)
		if err != nil {
			log.Println("error encoding assurance bitfield", err)
			return false
		}
		message = append(message, b...)
		messageHash := crypto.HashData(message)
		if !ed25519.Verify(validators[assurance.ValidatorIndex].Ed25519, append([]byte(signatureContextAvailable), messageHash[:]...), assurance.Signature[:]) {
			return false
		}
	}
	return true
}

// getAvailableWorkReports partially implements equation 28: W* ≺ (EA, ρ′) and 130: W ≡ [ρ†[c]w | c <- NC, ∑a∈EA af[c] > 2/3 V]
// we diverge from equation 28 and return available work reports instead of accumulatable
func getAvailableWorkReports(assurances block.AssurancesExtrinsic, coreAssignments state.CoreAssignments) []block.WorkReport {
	// Count assurances per core
	assuranceCounts := make([]int, common.TotalNumberOfCores)

	// Process each assurance
	for _, assurance := range assurances {
		for coreIndex := uint16(0); coreIndex < common.TotalNumberOfCores; coreIndex++ {
			if block.HasAssuranceForCore(assurance, coreIndex) {
				assuranceCounts[coreIndex]++
			}
		}
	}

	// Collect work reports that have sufficient assurances
	var availableReports []block.WorkReport
	threshold := (2 * common.NumberOfValidators) / 3 // 2/3 V

	for coreIndex := uint16(0); coreIndex < common.TotalNumberOfCores; coreIndex++ {
		if assuranceCounts[coreIndex] > threshold {
			if assignment := coreAssignments[coreIndex]; assignment.WorkReport != nil {
				availableReports = append(availableReports, *assignment.WorkReport)
			}
		}
	}

	return availableReports
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
func calculateNewValidatorStatistics(block block.Block, timeslot jamtime.Timeslot, validatorStatistics validator.ValidatorStatisticsState) validator.ValidatorStatisticsState {
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

// ParallelDelta implements equation 178 (∆*)
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
	return a.InvokePVM(accumulationState, serviceIndex, gasLimit, operands)
}
