package guaranteeing

import (
	"errors"
	"fmt"
	"log"
	"maps"
	"slices"

	"github.com/eigerco/strawberry/internal/crypto/ed25519"

	"github.com/eigerco/strawberry/internal/block"
	"github.com/eigerco/strawberry/internal/common"
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/jamtime"
	"github.com/eigerco/strawberry/internal/safemath"
	"github.com/eigerco/strawberry/internal/safrole"
	"github.com/eigerco/strawberry/internal/service"
	"github.com/eigerco/strawberry/internal/state"
	"github.com/eigerco/strawberry/internal/store"
	"github.com/eigerco/strawberry/internal/validator"
)

// Ancestry determines whether to validate that lookup anchor headers exist in the chain's ancestor set.
// GP: "We also require that we have a record of it; this is one of
// the few conditions which cannot be checked purely with
// on-chain state and must be checked by virtue of retain-
// ing the series of the last L headers as the ancestor set A."
// ∀x ∈ x : ∃h ∈ A : hT = xt ∧ H(h) = xl (eq. 11.35 v 0.7.0)
// TODO: Make this configurable. Currently the test vectors and traces `do not use ancestry.
// The conformance tests have the option to have it enabled or disabled.
const Ancestry = false

// ValidateGuaranteExtrinsicAndReturnReporters validates the guarantees extrinsic according to section 11.4.
// It performs all validity checks required for work report guarantees and returns the set of reporters.
// A specific order of the functions inside is required to pass the test vectors
func ValidateGuaranteExtrinsicAndReturnReporters(ge block.GuaranteesExtrinsic, s *state.State, newEntropyPool state.EntropyPool, chain *store.Chain, newTimeslot jamtime.Timeslot,
	intermediateRecentHistory state.RecentHistory, newBlockHeader block.Header, intermediateCoreAssignments state.CoreAssignments) (crypto.ED25519PublicKeySet, error) {
	if err := verifySortedUnique(ge); err != nil {
		return nil, err
	}

	if err := verifyAuth(ge, s.CoreAuthorizersPool); err != nil {
		return nil, err
	}
	if err := validateWorkReports(ge, s, intermediateRecentHistory, newBlockHeader, chain, intermediateCoreAssignments, newTimeslot); err != nil {
		return nil, err
	}
	reporters, err := verifySignatures(ge, s.ValidatorState, s.PastJudgements.OffendingValidators, newEntropyPool, newTimeslot)
	if err != nil {
		return nil, err
	}

	if err = validateGasLimits(ge, s.Services); err != nil {
		return nil, err
	}

	return reporters, nil
}

// CalculatePosteriorCoreAssignments updates core assignments with new guarantees.
// ∀c ∈ NC : ρ′[c] ≡ {(r, t ▸▸ τ′) if ∃(r, t, a) ∈ EG, rc = c | ρ‡[c] otherwise} (eq. 11.43 v 0.7.0)
func CalculatePosteriorCoreAssignments(ge block.GuaranteesExtrinsic, intermediateCoreAssignments state.CoreAssignments, newTimeslot jamtime.Timeslot) state.CoreAssignments {
	for _, g := range ge.Guarantees {
		intermediateCoreAssignments[g.WorkReport.CoreIndex] = &state.Assignment{
			WorkReport: g.WorkReport,
			Time:       newTimeslot,
		}
	}

	return intermediateCoreAssignments
}

// RotateSequence rotates the sequence by n positions modulo C.
// R(c, n) ≡ [(x + n) mod C | x ← c] (eq. 11.19 v0.7.0)
func RotateSequence(sequence []uint32, n uint32) []uint32 {
	rotated := make([]uint32, len(sequence))
	for i, x := range sequence {
		rotated[i] = (x + n) % uint32(common.TotalNumberOfCores)
	}
	return rotated
}

// PermuteAssignments generates the core assignments for validators.
// Implements Equation (11.20 v0.6.7): P(e, t) ≡ R(F([⌊C ⋅ i/V⌋ ∣i ∈ NV], e), ⌊t mod E/R⌋)
// P(e, t) ≡ R(F([⌊C · i/V⌋ | i ← N_V], e), ⌊(t mod E)/R⌋) (eq. 11.20 v0.7.0)
func PermuteAssignments(entropy crypto.Hash, timeslot jamtime.Timeslot) ([]uint32, error) {
	// [⌊C ⋅ i/V⌋ ∣i ∈ NV]
	coreIndices := make([]uint32, common.NumberOfValidators)
	for i := range uint32(common.NumberOfValidators) {
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

// DetermineValidatorsAndDataForPermutation determines which validator set and entropy to use for core assignments.
// Equations 11.21, 11.22, 11.26 (v0.7.0):
// From equation 11.26:
//
//	where (c,k) = {
//	  M  if ⌊τ'/R⌋ = ⌊t/R⌋
//	  M* otherwise
//	}
//
// Where:
//   - t  = guaranteeTimeslot (the timeslot when the guarantee was made)
//   - τ' = newTimeslot (the current block's timeslot)
//   - R  = ValidatorRotationPeriod
//
// Equation 11.21 (current rotation M):
//
//	M ≡ (P(η₂', τ'), Φ(κ'))
//
// Equation 11.22 (previous rotation M*):
//
//	M* ≡ (P(e, τ' - R), Φ(k))
//	where (e,k) = {
//	  (η₂', κ') if ⌊(τ'-R)/E⌋ = ⌊τ'/E⌋  // previous rotation in same epoch
//	  (η₃', λ') otherwise                // previous rotation in different epoch
//	}
//
// Where:
//   - η₂', η₃' = entropy from pools[2] and pools[3]
//   - κ' = current validators
//   - λ' = archived validators (from previous epoch)
//   - E = TimeslotsPerEpoch
func DetermineValidatorsAndDataForPermutation(
	guaranteeTimeslot jamtime.Timeslot, // t
	newTimeslot jamtime.Timeslot, // τ'
	entropyPool state.EntropyPool, // [η₀', η₁', η₂', η₃']
	offendingValidators []ed25519.PublicKey,
	currentValidators safrole.ValidatorsData, // κ'
	archivedValidators safrole.ValidatorsData, // λ'
) (safrole.ValidatorsData, crypto.Hash, jamtime.Timeslot, error) {
	currentRotation := newTimeslot / jamtime.ValidatorRotationPeriod
	guaranteeRotation := guaranteeTimeslot / jamtime.ValidatorRotationPeriod

	var entropy crypto.Hash
	var timeslotForPermutation jamtime.Timeslot
	var validators safrole.ValidatorsData

	if guaranteeRotation == currentRotation { // ⌊τ'/R⌋ = ⌊t/R⌋ → use M
		// Eq. 11.21: M ≡ (P(η₂', τ'), Φ(κ'))
		entropy = entropyPool[2]
		timeslotForPermutation = newTimeslot
		validators = currentValidators
	} else { // ⌊τ'/R⌋ ≠ ⌊t/R⌋ → use M*
		// Eq. 11.22: M* ≡ (P(e, τ' - R), Φ(k))
		var ok bool
		timeslotForPermutation, ok = safemath.Sub(newTimeslot, jamtime.ValidatorRotationPeriod)
		if !ok {
			return safrole.ValidatorsData{}, crypto.Hash{}, 0, errors.New("timeslot underflow")
		}

		currentEpochIndex := newTimeslot / jamtime.TimeslotsPerEpoch
		previousRotationEpochIndex := timeslotForPermutation / jamtime.TimeslotsPerEpoch

		if currentEpochIndex == previousRotationEpochIndex { // ⌊(τ'-R)/E⌋ = ⌊τ'/E⌋
			// (e,k) = (η₂', κ')
			entropy = entropyPool[2]
			validators = currentValidators
		} else { // ⌊(τ'-R)/E⌋ ≠ ⌊τ'/E⌋
			// (e,k) = (η₃', λ')
			entropy = entropyPool[3]
			validators = archivedValidators
		}
	}

	validators, nullifiedKeys := validator.NullifyOffenders(validators, offendingValidators)
	// If a banned validator was found to have participated, return an error
	if len(nullifiedKeys) > 0 {
		return safrole.ValidatorsData{}, crypto.Hash{}, 0, errors.New("banned validator")
	}
	return validators, entropy, timeslotForPermutation, nil
}

// EG ∈ ⟦{r ∈ R, t ∈ NT, a ∈ ⟦{NV,V̄}⟧2∶3}⟧∶C (eq. 11.23 v 0.7.0)
// EG = [g ∈ EG ^ ^(gr)c] (eq. 11.24 v 0.7.0)
// ∀g ∈ EG : ga = [(v, s) ∈ ga ︱︱v] (eq. 11.25 v 0.7.0)
func verifySortedUnique(ge block.GuaranteesExtrinsic) error {
	seenCores := map[uint16]struct{}{}
	var prevCore uint16

	for i, g := range ge.Guarantees {
		core := g.WorkReport.CoreIndex

		if _, exists := seenCores[core]; exists {
			return errors.New("out of order guarantee")
		}
		seenCores[core] = struct{}{}

		if i > 0 && core <= prevCore {
			return errors.New("out of order guarantee")
		}
		prevCore = core

		// Check all validator indices are within range
		for j := 0; j < len(g.Credentials); j++ {
			if g.Credentials[j].ValidatorIndex >= uint16(common.NumberOfValidators) {
				return fmt.Errorf("bad validator index")
			}
		}

		// Check credentials are sorted by validator index
		for j := 1; j < len(g.Credentials); j++ {
			prev := g.Credentials[j-1].ValidatorIndex
			curr := g.Credentials[j].ValidatorIndex
			if prev >= curr {
				return errors.New("not sorted or unique guarantors")
			}
		}
	}

	return nil
}

//	∀(r, t, a) ∈ E_G, ∀(v, s) ∈ a : {
//	  s ∈ V̄_(k_v)_e⟨X_G ⊕ H(r)⟩
//	  c_v = r_c ∧ R(⌊τ'/R⌋ - 1) ≤ t ≤ τ'
//	  k ∈ G ⇔ ∃(r, t, a) ∈ E_G, ∃(v, s) ∈ a : k = (k_v)_e
//	  where (c,k) = {
//	    M  if ⌊τ'/R⌋ = ⌊t/R⌋
//	    M* otherwise
//	  }
//	} (eq. 11.26 v0.7.0)
func verifySignatures(ge block.GuaranteesExtrinsic, validatorState validator.ValidatorState, offendingValidators []ed25519.PublicKey,
	entropyPool state.EntropyPool, newTimeslot jamtime.Timeslot) (crypto.ED25519PublicKeySet, error) {
	reporters := make(crypto.ED25519PublicKeySet)
	for _, g := range ge.Guarantees {
		// EG ∈ ⟦{r ∈ R, t ∈ NT, a ∈ ⟦{NV,V̄}⟧2∶3}⟧∶C (eq. 11.23 v 0.7.0)
		if len(g.Credentials) < 2 {
			return reporters, errors.New("insufficient guarantees")
		}
		validators, entropy, timeslotForPermutation, err := DetermineValidatorsAndDataForPermutation(
			g.Timeslot,
			newTimeslot,
			entropyPool,
			offendingValidators,
			validatorState.CurrentValidators,
			validatorState.ArchivedValidators,
		)

		// If a banned validator was found to have participated, return an error
		if err != nil {
			return reporters, err
		}

		coreAssignments, err := PermuteAssignments(entropy, timeslotForPermutation)
		if err != nil {
			return reporters, fmt.Errorf("failed to compute core assignments: %w", err)
		}

		// Generate work report hash
		reportHash, err := g.WorkReport.Hash()
		if err != nil {
			return reporters, fmt.Errorf("failed to marshal work report: %w", err)
		}
		message := append([]byte(state.SignatureContextGuarantee), reportHash[:]...)

		for _, c := range g.Credentials {
			if !isValidatorAssignedToCore(c.ValidatorIndex, g.WorkReport.CoreIndex, coreAssignments) {
				log.Printf("Validator %d not assigned to core %d", c.ValidatorIndex, g.WorkReport.CoreIndex)
				return reporters, errors.New("wrong assignment")
			}
			validatorKey := validators[c.ValidatorIndex].Ed25519
			// Verify signature
			sigValid := ed25519.Verify(validatorKey, message, c.Signature[:])
			if !sigValid {
				log.Printf("Invalid signature from validator %d", c.ValidatorIndex)
				log.Printf("  Key: %x", validatorKey)
				log.Printf("  Signature: %x", c.Signature[:])
				return reporters, errors.New("bad signature")
			}

			reporters.Add(validatorKey)
		}
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

// ∀r ∈ I : ρ‡[rc] = ∅ ∧ ra ∈ αrc (eq. 11.29 v0.7.0)(auth part only)
func verifyAuth(ge block.GuaranteesExtrinsic, cap state.CoreAuthorizersPool) error {
	for _, g := range ge.Guarantees {
		// Check if core index is valid
		if g.WorkReport.CoreIndex >= uint16(len(cap)) {
			return errors.New("bad core index")
		}
		// Validate core index is within bounds based on auth pools length
		if int(g.WorkReport.CoreIndex) >= len(cap) {
			return errors.New("bad core index")
		}
		// Verify authorizer exists in the core's authorization pool
		authFound := slices.Contains(cap[g.WorkReport.CoreIndex], g.WorkReport.AuthorizerHash)
		if !authFound {
			return errors.New("core unauthorized")
		}
	}
	return nil
}

// ∀r ∈ I : ∑d∈rd (dg) ≤ GA ∧ ∀d ∈ rd : dg ≥ δ[ds]g (eq. 11.30 v 0.7.0)
func validateGasLimits(ge block.GuaranteesExtrinsic, services service.ServiceState) error {
	for i, g := range ge.Guarantees {
		totalGas := uint64(0)
		for j, r := range g.WorkReport.WorkDigests {
			service, exists := services[r.ServiceId]
			if !exists {
				return errors.New("bad service id")
			}
			// Check minimum gas requirement: rg ≥ δ[rs]g
			if r.GasLimit < service.GasLimitForAccumulator {
				return fmt.Errorf("service item gas too low")
			}
			var ok bool
			totalGas, ok = safemath.Add(totalGas, r.GasLimit)
			if !ok {
				return fmt.Errorf("guarantee %d, work digest %d: gas overflow detected", i, j)
			}
		}

		// Check total gas limit: ∑(r∈wr) rg ≤ GA
		if totalGas > common.MaxAllocatedGasAccumulation {
			return fmt.Errorf("work report gas too high")
		}
	}
	return nil
}

// R(⌊τ'/R⌋ - 1) ≤ t ≤ τ' (eq. 11.26 v0.7.0)
func verifyGuaranteeAge(guarantee block.Guarantee, newTimeslot jamtime.Timeslot) error {
	guaranteeRotation := guarantee.Timeslot / jamtime.ValidatorRotationPeriod
	currentRotation := newTimeslot / jamtime.ValidatorRotationPeriod

	// Guarantee must not be from future timeslot
	if guarantee.Timeslot > newTimeslot {
		return errors.New("future report slot")
	}

	// If in same rotation or previous, valid
	if currentRotation-guaranteeRotation <= 1 {
		return nil
	}

	// Otherwise invalid (too old)
	return errors.New("report epoch before last")
}

// ∀x ∈ x : ∃y ∈ β†H : xa = yh ∧ xs = ys ∧ xb = yb (eq. 11.33 v 0.7.0)
func anchorBlockInRecentBlocks(context block.RefinementContext, intermediateRecentHistory state.RecentHistory) (bool, error) {
	for _, y := range intermediateRecentHistory.BlockHistory {
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

// ∀r ∈ R : |rl| + |(rc)p| ≤ J (eq. 11.3 v 0.7.0)
// ∀r ∈ R : |rt| + ∑d∈rd∩B |dl| ≤ WR (eq. 11.8 v 0.7.0)
// WR ≡ 48 ⋅ 2 10 (eq. 11.9 v 0.7.0)
func validateWorkReportProperties(ge block.GuaranteesExtrinsic) error {
	for _, g := range ge.Guarantees {
		if !g.WorkReport.DependenciesCountIsValid() {
			return errors.New("too many dependencies")
		}
		if !g.WorkReport.OutputSizeIsValid() {
			return errors.New("work report too big")
		}
	}
	return nil
}

// ρ‡[rc] = ∅  (part of eq. 11.29 v 0.7.0)
func validateCoreEngagement(ge block.GuaranteesExtrinsic, intermediateCoreAssignments state.CoreAssignments) error {
	for _, g := range ge.Guarantees {
		if intermediateCoreAssignments[g.WorkReport.CoreIndex] != nil {
			return errors.New("core engaged")
		}
	}
	return nil
}

// R(⌊τ′/R⌋ − 1) ≤ t ≤ τ′ (eq. 11.26 v 0.7.0)
func validateGuaranteeAges(ge block.GuaranteesExtrinsic, newTimeslot jamtime.Timeslot) error {
	for _, g := range ge.Guarantees {
		if err := verifyGuaranteeAge(g, newTimeslot); err != nil {
			return err
		}
	}
	return nil
}

// let x ≡ {rc | r ∈ I}, p ≡ {(rs)p | r ∈ I} (eq. 11.31 v 0.7.0)
func extractContextsAndHashes(ge block.GuaranteesExtrinsic) ([]block.RefinementContext, []crypto.Hash) {
	contexts := []block.RefinementContext{}
	extrinsicWorkPackageHashes := []crypto.Hash{}

	for _, g := range ge.Guarantees {
		contexts = append(contexts, g.WorkReport.RefinementContext)
		extrinsicWorkPackageHashes = append(extrinsicWorkPackageHashes, g.WorkReport.AvailabilitySpecification.WorkPackageHash)
	}

	return contexts, extrinsicWorkPackageHashes
}

// |p| = |I| (eq. 11.32 v 0.7.0)
func validateWorkPackageUniqueness(extrinsicWorkPackageHashes []crypto.Hash, ge block.GuaranteesExtrinsic) error {
	if len(extrinsicWorkPackageHashes) != len(ge.Guarantees) {
		return fmt.Errorf("cardinality of work-package hashes is not equal to the length of work-reports")
	}

	seen := make(map[crypto.Hash]struct{})
	for _, h := range extrinsicWorkPackageHashes {
		if _, exists := seen[h]; exists {
			return fmt.Errorf("duplicate package")
		}
		seen[h] = struct{}{}
	}
	return nil
}

func validateRefinementContexts(contexts []block.RefinementContext, intermediateRecentHistory state.RecentHistory,
	newBlockHeader block.Header, chain *store.Chain) error {

	for _, context := range contexts {
		// Validate anchor block in recent blocks
		// ∀x ∈ x : ∃y ∈ β†H : xa = yh ∧ xs = ys ∧ xb = yb (eq. 11.33 v 0.7.0)
		found, err := anchorBlockInRecentBlocks(context, intermediateRecentHistory)
		if !found {
			return err
		}

		// Validate lookup anchor timeslot
		// ∀x ∈ x : xt ≥ HT − L (eq. 11.34 v 0.7.0)
		var minValidTimeslot jamtime.Timeslot
		if newBlockHeader.TimeSlotIndex > state.MaxTimeslotsForLookupAnchor {
			minValidTimeslot = newBlockHeader.TimeSlotIndex - state.MaxTimeslotsForLookupAnchor
		} else {
			minValidTimeslot = 0 // Any timeslot is valid if we're within the first L slots
		}

		if context.LookupAnchor.Timeslot < minValidTimeslot {
			return fmt.Errorf("lookup anchor block (timeslot %d) not within the last %d timeslots (current timeslot: %d, minimum valid: %d)",
				context.LookupAnchor.Timeslot, state.MaxTimeslotsForLookupAnchor, newBlockHeader.TimeSlotIndex, minValidTimeslot)
		}

		if Ancestry {
			// Validate header exists in chain
			// ∀x ∈ x : ∃h ∈ A : hT = xt ∧ H(h) = xl (eq. 11.35 v 0.7.0)
			_, found, err := chain.FindHeader(func(ancestor block.Header) bool {
				ancestorHash, err := ancestor.Hash()
				if err != nil {
					return false
				}
				return ancestor.TimeSlotIndex == context.LookupAnchor.Timeslot && ancestorHash == context.LookupAnchor.HeaderHash
			})
			if err != nil {
				return fmt.Errorf("finding header: %w", err)
			}
			if !found {
				return fmt.Errorf("no record of header found")
			}
		}
	}
	return nil
}

func validateNoDuplicatePackages(extrinsicWorkPackageHashes []crypto.Hash, s *state.State) error {
	// let q = {(rs)p | (r,d) ∈ ω̃} (eq. 11.36 v 0.7.0)
	// q = work packages in accumulation queue
	accQueueReportWorkPackageHashes := make(map[crypto.Hash]struct{})
	for _, timeslot := range s.AccumulationQueue {
		for _, wr := range timeslot {
			accQueueReportWorkPackageHashes[wr.WorkReport.AvailabilitySpecification.WorkPackageHash] = struct{}{}
		}
	}
	// let a = {((rr)s)p | r ∈ ρ, r ≠ ∅} (eq. 11.37 v 0.7.0)
	// a = work packages pending availability
	pendingAvailabilityReportWorkPackageHashes := make(map[crypto.Hash]struct{})
	for _, c := range s.CoreAssignments {
		if c != nil {
			pendingAvailabilityReportWorkPackageHashes[c.WorkReport.AvailabilitySpecification.WorkPackageHash] = struct{}{}
		}
	}

	// ⋃x∈ξ x = accumulation history work packages
	accHistoryWorkPackageHashes := make(map[crypto.Hash]struct{})
	for _, hash := range s.AccumulationHistory {
		maps.Copy(accHistoryWorkPackageHashes, hash)
	}

	// Check for duplicates
	// ∀p ∈ p, p ∉ ⋃x∈βH K(xp) ∪ ⋃x∈ξ x ∪ q ∪ a (eq. 11.38 v 0.7.0)
	for _, h := range extrinsicWorkPackageHashes {
		// Check ⋃x∈βH K(xp) - work packages in recent history blocks
		for _, block := range s.RecentHistory.BlockHistory {
			if _, ok := block.Reported[h]; ok {
				return errors.New("duplicate package")
			}
		}
		// Check ⋃x∈ξ x - accumulation history
		if _, ok := accHistoryWorkPackageHashes[h]; ok {
			return errors.New("duplicate package")
		}
		// Check q - accumulation queue
		if _, ok := accQueueReportWorkPackageHashes[h]; ok {
			return errors.New("duplicate package")
		}
		// Check a - pending availability
		if _, ok := pendingAvailabilityReportWorkPackageHashes[h]; ok {
			return errors.New("duplicate package")
		}
	}

	return nil
}

// let p = {(((gr)s)p ↦ ((gr)s)e) | g ∈ EG} (eq. 11.40 v 0.7.0)
func createCurrentBlockMapping(ge block.GuaranteesExtrinsic) map[crypto.Hash]crypto.Hash {
	currentBlockMapping := make(map[crypto.Hash]crypto.Hash)
	for _, guarantee := range ge.Guarantees {
		workPackageHash := guarantee.WorkReport.AvailabilitySpecification.WorkPackageHash
		segmentRoot := guarantee.WorkReport.AvailabilitySpecification.SegmentRoot
		currentBlockMapping[workPackageHash] = segmentRoot
	}
	return currentBlockMapping
}

// ∀r ∈ I : rl ⊆ p ∪ ⋃b∈βH bp (eq. 11.41 v 0.7.0)
func validateSegmentRootLookups(ge block.GuaranteesExtrinsic, currentBlockMapping map[crypto.Hash]crypto.Hash,
	recentHistory state.RecentHistory) error {
	for _, g := range ge.Guarantees {
		segmentLookup := g.WorkReport.SegmentRootLookup
		for workPkgHash, expectedSegmentRoot := range segmentLookup {
			found := false
			// Check in current block mapping (p)
			if segRoot, ok := currentBlockMapping[workPkgHash]; ok && segRoot == expectedSegmentRoot {
				found = true
			}

			if !found {
				// Check in recent blocks (⋃b∈βH bp)
				for _, b := range recentHistory.BlockHistory {
					if segRoot, ok := b.Reported[workPkgHash]; ok && segRoot == expectedSegmentRoot {
						found = true
						break
					}
				}
			}
			if !found {
				return errors.New("segment root lookup invalid")
			}
		}
	}
	return nil
}

func validateDependencies(ge block.GuaranteesExtrinsic, extrinsicWorkPackageHashes []crypto.Hash,
	recentHistory state.RecentHistory) error {
	// ∀r ∈ I, ∀p ∈ (rc)p ∪ K(rl) : p ∈ p ∪ {x | x ∈ K(bp), b ∈ βH} (eq. 11.39 v 0.7.0)
	// Collect all dependencies
	dependencies := make(map[crypto.Hash]struct{})
	for _, g := range ge.Guarantees {
		// Add prerequisites (rc)p
		for _, prereq := range g.WorkReport.RefinementContext.PrerequisiteWorkPackage {
			dependencies[prereq] = struct{}{}
		}
		// Add segment-root lookup keys K(rl)
		for segmentKey := range g.WorkReport.SegmentRootLookup {
			dependencies[segmentKey] = struct{}{}
		}
	}

	// Validate all dependencies are available
	for dep := range dependencies {
		// Check if we have it in the current extrinsic (p)
		found := slices.Contains(extrinsicWorkPackageHashes, dep)

		// If not found, check in recent block history ({x | x ∈ K(bp), b ∈ βH})
		if !found {
			for _, b := range recentHistory.BlockHistory {
				if _, ok := b.Reported[dep]; ok {
					found = true
					break
				}
			}
		}
		if !found {
			return errors.New("dependency missing")
		}
	}

	return nil
}

// ∀r ∈ I, ∀d ∈ rd : dc = δ[ds]c (eq. 11.42 v 0.7.0)
func validateServiceDigests(ge block.GuaranteesExtrinsic, services service.ServiceState) error {
	for _, g := range ge.Guarantees {
		for _, wd := range g.WorkReport.WorkDigests {
			if _, exists := services[wd.ServiceId]; !exists {
				return errors.New("bad service id")
			}
			if wd.ServiceHashCode != services[wd.ServiceId].CodeHash {
				return errors.New("bad code hash")
			}
		}
	}
	return nil
}

func validateWorkReports(ge block.GuaranteesExtrinsic, s *state.State, intermediateRecentHistory state.RecentHistory,
	newBlockHeader block.Header, chain *store.Chain, intermediateCoreAssignments state.CoreAssignments, newTimeslot jamtime.Timeslot) error {

	// Validate basic work report properties (11.3, 11.8, 11.9)
	if err := validateWorkReportProperties(ge); err != nil {
		return err
	}

	// Validate core assignments (11.29)
	if err := validateCoreEngagement(ge, intermediateCoreAssignments); err != nil {
		return err
	}

	// Validate guarantee age (11.26)
	if err := validateGuaranteeAges(ge, newTimeslot); err != nil {
		return err
	}

	// Extract contexts and work package hashes (11.31)
	contexts, extrinsicWorkPackageHashes := extractContextsAndHashes(ge)

	// Validate work package uniqueness (11.32)
	if err := validateWorkPackageUniqueness(extrinsicWorkPackageHashes, ge); err != nil {
		return err
	}

	// Validate refinement contexts (11.33, 11.34, 11.35)
	if err := validateRefinementContexts(contexts, intermediateRecentHistory, newBlockHeader, chain); err != nil {
		return err
	}

	// Validate no duplicate packages (11.36, 11.37, 11.38)
	if err := validateNoDuplicatePackages(extrinsicWorkPackageHashes, s); err != nil {
		return err
	}

	// Create current block mapping (11.40)
	currentBlockMapping := createCurrentBlockMapping(ge)

	// Validate segment root lookups (11.41)
	if err := validateSegmentRootLookups(ge, currentBlockMapping, s.RecentHistory); err != nil {
		return err
	}

	// Validate dependencies (11.39)
	if err := validateDependencies(ge, extrinsicWorkPackageHashes, s.RecentHistory); err != nil {
		return err
	}

	// Validate service digests (11.42)
	if err := validateServiceDigests(ge, s.Services); err != nil {
		return err
	}

	return nil
}
