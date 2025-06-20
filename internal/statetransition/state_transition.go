package statetransition

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"
	"log"
	"maps"
	"math"
	"slices"
	"sort"
	"sync"

	"github.com/eigerco/strawberry/internal/block"
	"github.com/eigerco/strawberry/internal/common"
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/crypto/bandersnatch"
	"github.com/eigerco/strawberry/internal/disputes"
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

	prevTimeSlot := s.TimeslotIndex
	newTimeSlot := CalculateNewTimeState(newBlock.Header)

	intermediateRecentHistory := CalculateIntermediateRecentHistory(newBlock.Header, s.RecentHistory)
	// TODO: this should probably be passed it explicitly to functions below that need it.
	s.RecentHistory = intermediateRecentHistory

	if err := ValidateExtrinsicGuarantees(newBlock.Header, s, newBlock.Extrinsic.EG, s.CoreAssignments, newTimeSlot, chain); err != nil {
		return fmt.Errorf("extrinsic guarantees validation failed, err: %w", err)
	}

	intermediateCoreAssignments := CalculateIntermediateCoreAssignmentsFromExtrinsics(newBlock.Extrinsic.ED, s.CoreAssignments)

	newJudgements, err := CalculateNewJudgements(prevTimeSlot, newBlock.Extrinsic.ED, s.PastJudgements, s.ValidatorState)
	if err != nil {
		return err
	}

	// Update SAFROLE state.
	safroleInput, err := NewSafroleInputFromBlock(newBlock)
	if err != nil {
		return err
	}
	newEntropyPool, newValidatorState, _, err := UpdateSafroleState(
		safroleInput,
		prevTimeSlot,
		s.EntropyPool,
		s.ValidatorState,
		newJudgements.OffendingValidators)
	if err != nil {
		return err
	}

	intermediateCoreAssignments, _, err = CalculateIntermediateCoreFromAssurances(s.ValidatorState.CurrentValidators, intermediateCoreAssignments, newBlock.Header, newBlock.Extrinsic.EA)
	if err != nil {
		return err
	}

	newCoreAssignments, reporters, err := CalculateNewCoreAssignments(newBlock.Extrinsic.EG, intermediateCoreAssignments, s.ValidatorState, newTimeSlot, newEntropyPool)
	if err != nil {
		return err
	}

	workReports := GetAvailableWorkReports(newCoreAssignments)

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
		workReports,
	)
	finalServicesState, err := CalculateIntermediateServiceState(newBlock.Extrinsic.EP, postAccumulationServiceState, newBlock.Header.TimeSlotIndex)
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
// R(d, s, h, l) ≡ h ∉ d[s]p ∧ d[s]l[(h, l)] = [] (eq. 12.30 v0.6.3)
func preimageHasBeenSolicited(serviceState service.ServiceState, serviceIndex block.ServiceId, preimageHash crypto.Hash, preimageLength service.PreimageLength) bool {
	account, ok := serviceState[serviceIndex]
	if !ok {
		return false
	}
	_, preimageLookupExists := account.PreimageLookup[preimageHash]

	metaKey := service.PreImageMetaKey{Hash: preimageHash, Length: preimageLength}
	meta, metaExists := account.PreimageMeta[metaKey]

	return !preimageLookupExists && (metaExists && len(meta) == 0)
}

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

// CalculateIntermediateServiceState implements Equations 12.28–12.33 v0.6.3
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
func CalculateIntermediateServiceState(
	preimages block.PreimageExtrinsic,
	serviceState service.ServiceState,
	newTimeslot jamtime.Timeslot,
) (service.ServiceState, error) {
	if !isPreimagesSortedUnique(preimages) {
		return serviceState, errors.New("preimages not sorted unique")
	}

	newServiceState := serviceState.Clone()

	for _, preimage := range preimages {
		serviceId := block.ServiceId(preimage.ServiceIndex)
		preimageHash := crypto.HashData(preimage.Data)
		preimageLength := service.PreimageLength(len(preimage.Data))

		// ∀(s, p) ∈ E_P∶ R(δ, s, H(p), |p|) (12.31 v0.6.3)
		if !preimageHasBeenSolicited(serviceState, serviceId, preimageHash, preimageLength) {
			return nil, errors.New("preimage unneeded")
		}

		// Eq. 12.33 v0.6.3:
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

	return newServiceState, nil
}

// CalculateIntermediateCoreAssignmentsFromExtrinsics processes dispute verdicts to clear
// work-reports from cores that have been judged as bad or wonky Equation 10.15(v0.6.7):
// Equation 4.12(v0.6.7): ρ† ≺ (ED , ρ)
//
//	∀c ∈ NC : ρ†[c] = {
//	  ∅ if {(H(ρ[c]w), t) ∈ V, t < ⌊2V/3⌋}
//	  ρ[c] otherwise
//	}
//
// This ensures that work-reports without a 2/3+1 supermajority of positive judgments
// are removed from their assigned cores before accumulation can occur. This is a critical
// security mechanism that prevents invalid or disputed work from being accumulated into
// the chain state.
func CalculateIntermediateCoreAssignmentsFromExtrinsics(de block.DisputeExtrinsic, coreAssignments state.CoreAssignments) state.CoreAssignments {
	newAssignments := coreAssignments // Create a copy of the current assignments

	// Process each verdict in the disputes
	for _, v := range de.Verdicts {
		verdictReportHash := v.ReportHash
		positiveJudgments := disputes.CountPositiveJudgements(v)

		// If less than 2/3+1 supermajority of positive judgments, the work-report is
		// considered either bad (0 positive) or wonky (1/3 positive), and must be
		// cleared from its core to prevent accumulation
		if positiveJudgments < disputes.DisputeVoteGood {
			// Search all cores to find where this work-report is assigned
			for c := uint16(0); c < common.TotalNumberOfCores; c++ {
				if newAssignments[c] == nil {
					continue
				}

				// Hash the work-report currently on this core to check if it matches
				coreReportHash, err := newAssignments[c].WorkReport.Hash()
				if err != nil {
					log.Printf("Failed to hash work report on core %d while clearing assignments for verdict with %d/%d positive votes: %v",
						c, positiveJudgments, disputes.DisputeVoteGood, err)
					continue
				}

				// If this core has the disputed work-report, clear it
				if coreReportHash == verdictReportHash {
					newAssignments[c] = nil // Clear the assignment
				}
			}
		}
		// Note: Work-reports with 2/3+1 positive judgments (good) remain on their cores
		// and can proceed to accumulation
	}

	return newAssignments
}

// CalculateIntermediateCoreAssignments implements equations
//
//	4.13: ρ‡ ≺ (EA, ρ†)
//	4.15: W* ≺ (EA, ρ†). Note there's a typo in the paper, which states ρ' but that isn't correct.
//
// It calculates the intermediate core assignments based on availability
// assurances, and also returns the set of now avaiable work reports.
// (GP v0.6.5)
func CalculateIntermediateCoreAssignments(assurances block.AssurancesExtrinsic, coreAssignments state.CoreAssignments, header block.Header) (state.CoreAssignments, []*block.WorkReport, error) {
	// Initialize availability count for each core
	availabilityCounts := make(map[uint16]int)

	// Process each assurance in the AssurancesExtrinsic (EA)
	// Check the availability status for each core in this assurance
	for coreIndex := range common.TotalNumberOfCores {
		for _, assurance := range assurances {
			// Check if the bit corresponding to this core is set (1) in the Bitfield
			// See equation 11.15: af[c] ⇒ ρ†[c] ≠ ∅
			if assurance.IsForCore(coreIndex) {
				if coreAssignments[coreIndex] == nil {
					return coreAssignments, nil, ErrCoreNotEngaged
				}
				// If set, increment the availability count for this core
				availabilityCounts[coreIndex]++
			}
		}
	}

	// W, the set of work reports that have become available. (see equation 11.16)
	var availableReports []*block.WorkReport
	// Update assignments based on availability
	// This implements equation 11.17:
	// ∀c ∈ NC : ρ‡[c] ≡ { ∅ if ρ[c]w ∈ W ∨ Ht ≥ ρ†[c]t + U
	//                    ρ†[c] otherwise }
	// It also implements 11.16 by adding any reports that are now available to W.
	for coreIndex := range common.TotalNumberOfCores {
		availCountForCore, ok := availabilityCounts[coreIndex]
		// Remove core if:
		// 1. There are availability assurances for this core, and they exceed the threshold, i.e > 2/3 of validators are assuring
		// 2. Assignment report is stale, the report is older than U timeslots ago and should timeout.
		if ok && availCountForCore > common.AvailabilityThreshold {
			// Add any report that is made available to the W set. Note this
			// includes reports that could already be timed out. We are lenient
			// here, as long as they are made available they get added to the
			// set.
			availableReports = append(availableReports, coreAssignments[coreIndex].WorkReport)
			coreAssignments[coreIndex] = nil
		}
		// Any report that isn't lucky enough to be made available is timed out and removed.
		if isAssignmentStale(coreAssignments[coreIndex], header.TimeSlotIndex) {
			coreAssignments[coreIndex] = nil
		}
	}

	// Return the new intermediate CoreAssignments (ρ‡), along with the newly available reports. (W)
	return coreAssignments, availableReports, nil
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
}

func NewSafroleInputFromBlock(block block.Block) (SafroleInput, error) {
	entropy, err := bandersnatch.OutputHash(block.Header.VRFSignature)
	if err != nil {
		return SafroleInput{}, err
	}

	// TODO - might want to make a deep copy for ticket proofs and offenders
	// here, but should be ok since it's read only.
	return SafroleInput{
		TimeSlot: block.Header.TimeSlotIndex,
		Tickets:  block.Extrinsic.ET.TicketProofs,
		Entropy:  entropy,
	}, nil
}

// Output from UpdateSafroleState.
type SafroleOutput struct {
	// H_e
	EpochMark *block.EpochMarker
	// H_w
	WinningTicketMark *block.WinningTicketMarker

	// Entropies for use by downstream functions that might also use this output.
	TicketEntropy  crypto.Hash // n_2
	SealingEntropy crypto.Hash // n_3
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

	ringVerifier, err := safstate.NextValidators.RingVerifier()
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
	offenders []ed25519.PublicKey,
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
	output := SafroleOutput{
		TicketEntropy:  newEntropyPool[2],
		SealingEntropy: newEntropyPool[3],
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
		newValidatorState.SafroleState.NextValidators = validator.NullifyOffenders(validatorState.QueuedValidators, offenders)
		newValidatorState.CurrentValidators = validatorState.SafroleState.NextValidators
		newValidatorState.ArchivedValidators = validatorState.CurrentValidators

		// Calculate new ring commitment. (γ_z) . Apply the O function from equation 58.
		//  Equation 58: z = O([kb S k <− γ′k])
		ringCommitment, err := newValidatorState.SafroleState.NextValidators.RingCommitment()
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
			output.EpochMark.Keys[i] = block.ValidatorKeys{
				Bandersnatch: vd.Bandersnatch,
				Ed25519:      vd.Ed25519,
			}
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

	// Process incoming tickets.  Check if we're still allowed to submit
	// tickets. An implication of equation 75. m' < Y to submit.
	if !nextTimeSlot.IsTicketSubmissionPeriod() && len(input.Tickets) > 0 {
		return entropyPool, validatorState, SafroleOutput{}, errors.New("unexpected ticket")
	}

	if len(input.Tickets) > 0 {
		// Validate ticket proofs and produce tickets. Tickets produced are n.
		// As in equation 76.
		tickets, err := calculateTickets(newValidatorState.SafroleState, newEntropyPool, input.Tickets)
		if err != nil {
			return entropyPool, validatorState, SafroleOutput{}, err
		}

		// Update the accumulator γ_a.
		// Equation 79: γ′a ≡ [xy^^ x ∈ n ∪ {∅ if e′ > e, γa otherwise}]E (v.0.4.5)
		// Combine existing and new tickets.
		accumulator := newValidatorState.SafroleState.TicketAccumulator
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

// CalculateNewJudgements Equation 4.11(v0.6.7): ψ′ ≺ (ED, ψ)
// Equations 10.16-10.19(v0.6.7):
// ψ'g ≡ ψg ∪ {r | {r, ⌊2/3V⌋ + 1} ∈ V}
// ψ'b ≡ ψb ∪ {r | {r, 0} ∈ V}
// ψ'w ≡ ψw ∪ {r | {r, ⌊1/3V⌋} ∈ V}
// ψ'o ≡ ψo ∪ {k | (r, k, s) ∈ c} ∪ {k | (r, v, k, s) ∈ f}
func CalculateNewJudgements(prevTimeSlot jamtime.Timeslot, de block.DisputeExtrinsic, stateJudgements state.Judgements, validators validator.ValidatorState) (state.Judgements, error) {
	newJudgements, err := disputes.ValidateDisputesExtrinsicAndProduceJudgements(prevTimeSlot, de, validators, stateJudgements)
	if err != nil {
		return stateJudgements, err
	}

	return newJudgements, nil
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
		rotationIndex := uint32(newTimeslot / jamtime.ValidatorRotationPeriod)
		var previousRotationStart uint32
		if rotationIndex == 0 {
			previousRotationStart = 0
		} else {
			previousRotationStart = (rotationIndex - 1) * uint32(jamtime.ValidatorRotationPeriod)
		}

		if uint32(guarantee.Timeslot) < previousRotationStart ||
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

	for _, recentBlock := range currentState.RecentHistory.BlockHistory {
		for key, val := range recentBlock.Reported {
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
	for _, block := range currentState.RecentHistory.BlockHistory {
		for hash := range block.Reported {
			extrinsicWorkPackages[hash] = block.Reported[hash]
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
	for _, y := range currentState.RecentHistory.BlockHistory {
		if context.Anchor.HeaderHash != y.HeaderHash {
			continue
		}

		// Found block but state root doesn't match
		if context.Anchor.PosteriorStateRoot != y.StateRoot {
			return false, fmt.Errorf("bad state root")
		}

		// Block found, check beefy root
		beefyRoot := y.BeefyRoot
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
	currentRotation := currentTimeslot / jamtime.ValidatorRotationPeriod
	guaranteeRotation := guaranteeTimeslot / jamtime.ValidatorRotationPeriod

	var entropy crypto.Hash
	var timeslotForPermutation jamtime.Timeslot
	var validators safrole.ValidatorsData

	// G ≡ (P(η₂', τ'), Φ(κ')) for current rotation
	if guaranteeRotation == currentRotation {
		entropy = entropyPool[2]
		timeslotForPermutation = currentTimeslot
		validators = currentValidators
	} else {
		timeslotForPermutation = currentTimeslot - jamtime.ValidatorRotationPeriod
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
	guaranteeRotation := guarantee.Timeslot / jamtime.ValidatorRotationPeriod
	currentRotation := currentTimeslot / jamtime.ValidatorRotationPeriod

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
	rotationAmount := uint32(timeslot % jamtime.TimeslotsPerEpoch / jamtime.ValidatorRotationPeriod)

	// R(F([⌊C ⋅ i/V⌋ ∣i ∈ NV], e), ⌊(t mod E)/R⌋)
	rotatedSequence := RotateSequence(shuffledSequence, rotationAmount)

	return rotatedSequence, nil
}

// CalculateWorkReportsAndAccumulate implements equations. We pass W instead of W* because we also need WQ for
// updating the state queue.
// eq. 4.16: (ϑ′, ξ′, δ‡, χ′, ι′, φ′, θ′, I, X) ≺ (W*, ϑ, ξ, δ, χ, ι, φ, τ, τ′)
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

	accumulator := NewAccumulator(currentState, header, newTimeslot)
	// let (n, o, t, θ′, u) = ∆+(g, W∗, (χ, δ, ι, φ), χg) (eq. 12.22)
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

	// (χ′, δ†, ι′, φ′) ≡ o (eq. 12.23)
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

	// N(s) ≡ [r | w <− W*...n, r <− w_r, r_s = s] (eq. 12.26)
	accumulateCountBySvc := map[block.ServiceId]uint32{}
	for _, workReport := range accumulatableWorkReports[:accumulatedCount] {
		for _, result := range workReport.WorkResults {
			accumulateCountBySvc[result.ServiceId]++
		}
	}

	// I ≡ {s ↦([∑(s,u)∈u] (u), |N(s)|) | N(s) ≠ []} (eq. 12.25)
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

	// x  = {s ↦ ΨT(δ†, τ′, s, R(t, s)) | (s ↦ a) ∈ δ†} (eq. 12.28)
	// δ‡ ≡ {s ↦ a′ T (s ↦ (a, u)) ∈ x} (12.29)
	postAccumulationServiceState = make(service.ServiceState)

	// X ≡ {d ↦ (|R(t, d)|, u) | R(t, d) ≠ [], ∃a ∶ x[d] = (a, u)} (eq. 12.31)
	transfersStats = DeferredTransfersStats{}

	for serviceId := range intermediateServiceState {
		// R(t, d)
		receiverTransfers := transfersForReceiver(transfers, serviceId)

		newService, gasUsed := accumulator.InvokePVMOnTransfer(
			intermediateServiceState,
			newTimeslot,
			serviceId,
			receiverTransfers,
		)

		if _, ok := accumulationStats[serviceId]; !ok {
			newService.MostRecentAccumulationTimeslot = newTimeslot
		}

		postAccumulationServiceState[serviceId] = newService

		// R(t, d) ≠ []
		if len(receiverTransfers) > 0 {
			transfersStats[serviceId] = DeferredTransfersStatEntry{
				OnTransfersCount:   uint32(len(receiverTransfers)),
				OnTransfersGasUsed: gasUsed,
			}
		}
	}

	// ξ′E−1 = P(W*...n) (eq. 12.25)
	// ∀i ∈ NE−1 ∶ ξ′i ≡ ξi+1 (eq. 12.26)
	newAccumulationHistory = state.AccumulationHistory(append(
		currentState.AccumulationHistory[1:],
		getWorkPackageHashes(accumulatableWorkReports[:accumulatedCount]),
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

// transfersForReceiver R(t ⟦T⟧, d NS) → ⟦T⟧ (eq. 12.27)
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

// assuranceIsOrderedByValidatorIndex (126) ∀i ∈ {1 ... |E_A|} ∶ EA[i − 1]v < EA[i]v
func assuranceIsOrderedByValidatorIndex(assurances block.AssurancesExtrinsic) bool {
	return slices.IsSortedFunc(assurances, func(a, b block.Assurance) int {
		if a.ValidatorIndex > b.ValidatorIndex {
			return 1
		}
		return -1
	})
}

// CalculateIntermediateCoreFromAssurances implements equations
//
//	4.13: ρ‡ ≺ (EA, ρ†)
//	4.15: W* ≺ (EA, ρ†). Note there's a typo in the paper, which states ρ' but that isn't correct.
//
// It calculates the intermediate core assignments based on availability
// assurances, and also returns the set of now avaiable work reports. It also
// validates that the assurance extrinsic, checking signatures and that ordering
// is correct with no duplicates. Signatures should be checked using the prior
// state active validators, ie κ. (GP v0.6.5)
func CalculateIntermediateCoreFromAssurances(validators safrole.ValidatorsData, assignments state.CoreAssignments, header block.Header, assurances block.AssurancesExtrinsic) (state.CoreAssignments, []*block.WorkReport, error) {
	if err := validateAssurancesSignature(validators, header, assurances); err != nil {
		return assignments, nil, err
	}

	if !assuranceIsOrderedByValidatorIndex(assurances) {
		return assignments, nil, fmt.Errorf("not sorted or unique assurers")
	}

	return CalculateIntermediateCoreAssignments(assurances, assignments, header)
}

// validateAssurancesSignature (127) ∀a ∈ EA ∶ as ∈ Eκ′[av ]e ⟨XA ⌢ H(E(Hp, af ))⟩
func validateAssurancesSignature(validators safrole.ValidatorsData, header block.Header, assurances block.AssurancesExtrinsic) error {
	for _, assurance := range assurances {
		if int(assurance.ValidatorIndex) >= common.NumberOfValidators || validators[assurance.ValidatorIndex].IsEmpty() {
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
		for _, workResult := range workReport.WorkResults {

			newCoreStats[coreIndex].Imports += workResult.ImportsCount
			newCoreStats[coreIndex].Exports += workResult.ExportsCount
			newCoreStats[coreIndex].ExtrinsicCount += workResult.ExtrinsicCount
			newCoreStats[coreIndex].ExtrinsicSize += workResult.ExtrinsicSize
			newCoreStats[coreIndex].GasUsed += workResult.GasUsed
			// TODO this might be out of the loop, but the equation looks like it's done for each result.
			newCoreStats[coreIndex].BundleSize += workReport.WorkPackageSpecification.AuditableWorkBundleLength

		}

	}

	// Equation 13.10
	// ∑ w ∈W, wc=c (ws)_l + W_G⌈(ws)_n65/64⌉
	// 65/64 likely adds overhead for proofs which require one segment for every 64 segments.
	for _, workReport := range availableReports {
		coreIndex := workReport.CoreIndex

		l := workReport.WorkPackageSpecification.AuditableWorkBundleLength
		n := workReport.WorkPackageSpecification.SegmentCount
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
		for _, workResult := range workReport.WorkResults {
			serviceID := block.ServiceId(workResult.ServiceId)
			record := newServiceStats[serviceID]

			record.Imports += uint32(workResult.ImportsCount)
			record.Exports += uint32(workResult.ExportsCount)
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

// ServiceHashPairs B ≡ {(NS , H)} (eq. 12.15)
type ServiceHashPairs []state.ServiceHashPair

// ServiceGasPairs U ≡ ⟦(NS , NG)⟧
type ServiceGasPairs []ServiceGasPair

// AccumulationStats I ∈ D⟨NS →(NG, N)⟩ (eq. 12.24)
type AccumulationStats map[block.ServiceId]AccumulationStatEntry

type AccumulationStatEntry struct {
	AccumulateGasUsed uint64
	AccumulateCount   uint32
}

// DeferredTransfersStats X ∈ D⟨NS →(N, NG)⟩ (eq. 12.30)
type DeferredTransfersStats map[block.ServiceId]DeferredTransfersStatEntry

type DeferredTransfersStatEntry struct {
	OnTransfersCount   uint32
	OnTransfersGasUsed uint64
}

type ServiceGasPair struct {
	ServiceId block.ServiceId
	Gas       uint64
}

// SequentialDelta implements equation 12.16 (∆+(NG, ⟦W⟧, U, D⟨NS → NG⟩) → (N, U, ⟦T⟧, B, U))
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

// ParallelDelta implements equation 12.17 (∆*)
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
		for _, result := range report.WorkResults {
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
			accState, deferredTransfers, resultHash, gasUsed, preimageProvisions := a.Delta1(initialAccState, workReports, alwaysAccumulate, serviceId)
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
			// n = ⋃[s∈s]({(∆1(o, w, f, s)o)d ∖ K(d ∖ {s})})
			// m = ⋃[s∈s](K(d) ∖ K((∆1(o, w, f , s)o)d))
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
		accState, _, _, _, _ := a.Delta1(initialAccState, workReports, alwaysAccumulate, serviceId)
		mu.Lock()
		defer mu.Unlock()

		newAccState.ManagerServiceId = accState.ManagerServiceId
		intermediateAssignServiceId = accState.AssignedServiceIds
		intermediateDesignateServiceId = accState.DesignateServiceId
		newAccState.AmountOfGasPerServiceId = accState.AmountOfGasPerServiceId
	}(initialAccState.ManagerServiceId)

	// i′ = (∆1(o, w, f, v)o)i
	wg.Add(1)
	go func(serviceId block.ServiceId) {
		defer wg.Done()

		// Process single service using Delta1
		accState, _, _, _, _ := a.Delta1(initialAccState, workReports, alwaysAccumulate, serviceId)
		mu.Lock()
		defer mu.Unlock()

		newAccState.ValidatorKeys = accState.ValidatorKeys
	}(newAccState.DesignateServiceId)

	// ∀c ∈ NC ∶ q′c = (∆1(o, w, f , a_c)o)q
	for core, assignServiceId := range newAccState.AssignedServiceIds {
		wg.Add(1)
		go func(serviceId block.ServiceId) {
			defer wg.Done()

			// Process single service using Delta1
			accState, _, _, _, _ := a.Delta1(initialAccState, workReports, alwaysAccumulate, serviceId)
			mu.Lock()
			newAccState.PendingAuthorizersQueues[core] = accState.PendingAuthorizersQueues[core]
			defer mu.Unlock()
		}(assignServiceId)
	}

	// Wait for manager, assign, designate and worker services
	wg.Wait()

	// d′ = P ((d ∪ n) ∖ m, [⋃s∈s] ∆1(o, w, f , s)p)
	newAccState.ServiceState = a.preimageIntegration(newAccState.ServiceState, allPreimageProvisions)

	// ∀c ∈ NC ∶ a′_c = ((∆1(o, w, f, a*_c )o)a)c
	for core, assignServiceId := range intermediateAssignServiceId {
		wg.Add(1)
		go func(serviceId block.ServiceId) {
			defer wg.Done()

			// Process single service using Delta1
			accState, _, _, _, _ := a.Delta1(initialAccState, workReports, alwaysAccumulate, serviceId)
			mu.Lock()
			newAccState.AssignedServiceIds[core] = accState.AssignedServiceIds[core]
			defer mu.Unlock()
		}(assignServiceId)
	}

	// v′ = (∆1(o, w, f , v*)o)v
	wg.Add(1)
	go func(serviceId block.ServiceId) {
		defer wg.Done()

		// Process single service using Delta1
		accState, _, _, _, _ := a.Delta1(initialAccState, workReports, alwaysAccumulate, serviceId)
		mu.Lock()
		defer mu.Unlock()
		newAccState.DesignateServiceId = accState.DesignateServiceId
	}(intermediateDesignateServiceId)

	// Wait for the intermediate assign and designate services id assign
	wg.Wait()

	// Sort accumulation pairs by service ID to ensure deterministic output
	sort.Slice(accumHashPairs, func(i, j int) bool {
		return accumHashPairs[i].ServiceId < accumHashPairs[j].ServiceId
	})

	return newAccState, allTransfers, accumHashPairs, accumGasPairs
}

// Delta1 implements equation 12.19 ∆1 (U, ⟦W⟧, D⟨NS → NG⟩, NS ) → (U, ⟦T⟧, H?, NG)
func (a *Accumulator) Delta1(
	accumulationState state.AccumulationState,
	workReports []block.WorkReport,
	alwaysAccumulate map[block.ServiceId]uint64, // D⟨NS → NG⟩
	serviceIndex block.ServiceId, // NS
) (state.AccumulationState, []service.DeferredTransfer, *crypto.Hash, uint64, []polkavm.ProvidedPreimage) {
	// Calculate gas limit (g)
	gasLimit := uint64(0)
	if gas, exists := alwaysAccumulate[serviceIndex]; exists {
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
					WorkPackageHash:   report.WorkPackageSpecification.WorkPackageHash,
					SegmentRoot:       report.WorkPackageSpecification.SegmentRoot,
					AuthorizationHash: report.AuthorizerHash,
					Output:            report.Output,
					PayloadHash:       result.PayloadHash,
					GasLimit:          result.GasPrioritizationRatio,
					OutputOrError:     result.Output,
				}
				operands = append(operands, operand)
			}
		}
	}

	// InvokePVM VM for accumulation (ΨA)
	return a.InvokePVM(accumulationState, a.newTimeslot, serviceIndex, gasLimit, operands)
}

// P(d D⟨NS → A⟩,p {(NS , Y)}) → D⟨NS → A⟩
func (a *Accumulator) preimageIntegration(services service.ServiceState, preimages []polkavm.ProvidedPreimage) service.ServiceState {
	servicesWithPreimages := services.Clone()

	// ∀(s, i) ∈ p, s ∈ K(d), d[s]l[H(i), |i|] = []∶
	for _, preimage := range preimages {
		preimageHash := crypto.HashData(preimage.Data)
		if _, ok := services[preimage.ServiceId]; ok {
			key := service.PreImageMetaKey{
				Hash:   preimageHash,
				Length: service.PreimageLength(len(preimage.Data)),
			}

			if timeslots := services[preimage.ServiceId].PreimageMeta[key]; len(timeslots) == 0 {
				// d′ where d′ = d except:
				// d′[s]l[H(i), |i|] = [τ′]
				// d′[s]p[H(i)] = i
				servicesWithPreimages[preimage.ServiceId].PreimageMeta[key] = service.PreimageHistoricalTimeslots{a.newTimeslot}
				servicesWithPreimages[preimage.ServiceId].PreimageLookup[preimageHash] = preimage.Data
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
