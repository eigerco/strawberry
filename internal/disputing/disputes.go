package disputing

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"log"

	"slices"

	"github.com/eigerco/strawberry/internal/block"
	"github.com/eigerco/strawberry/internal/common"
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/jamtime"
	"github.com/eigerco/strawberry/internal/safrole"
	"github.com/eigerco/strawberry/internal/state"
	"github.com/eigerco/strawberry/internal/validator"
)

const (
	DisputeVoteBad   uint16 = 0                                       // 0 positive votes - report is bad
	DisputeVoteWonky uint16 = common.NumberOfValidators / 3           // 1/3 positive votes - report is wonky/unknowable
	DisputeVoteGood  uint16 = (2 * common.NumberOfValidators / 3) + 1 // 2/3+1 positive votes - report is good
)

// CalculateIntermediateCoreAssignmentsFromExtrinsics processes dispute verdicts to clear
// work-reports from cores that have been judged as bad or wonky
// ∀c ∈ NC : ρ†[c] = {∅ if (H(ρ[c]r), t) ∈ v, t < ⌊2/3V⌋; ρ[c] otherwise} (eq. 10.15 v 0.7.0)
// This ensures that work-reports without a 2/3+1 supermajority of positive judgments
// are removed from their assigned cores before accumulation can occur. This is a critical
// security mechanism that prevents invalid or disputed work from being accumulated into
// the chain state.
func CalculateIntermediateCoreAssignmentsFromExtrinsics(de block.DisputeExtrinsic, coreAssignments state.CoreAssignments) state.CoreAssignments {
	newAssignments := coreAssignments // Create a copy of the current assignments

	// Process each verdict in the disputes
	for _, v := range de.Verdicts {
		verdictReportHash := v.ReportHash
		positiveJudgments := CountPositiveJudgements(v)

		// If less than 2/3+1 supermajority of positive judgments, the work-report is
		// considered either bad (0 positive) or wonky (1/3 positive), and must be
		// cleared from its core to prevent accumulation
		if positiveJudgments < DisputeVoteGood {
			// Search all cores to find where this work-report is assigned
			for c := uint16(0); c < common.TotalNumberOfCores; c++ {
				if newAssignments[c] == nil {
					continue
				}

				// Hash the work-report currently on this core to check if it matches
				coreReportHash, err := newAssignments[c].WorkReport.Hash()
				if err != nil {
					log.Printf("Failed to hash work report on core %d while clearing assignments for verdict with %d/%d positive votes: %v",
						c, positiveJudgments, DisputeVoteGood, err)
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

// verifyVerdictSignatures verifies the signatures of all judgments in a verdict
// ∀(r,a,j) ∈ EV, ∀(v,i,s) ∈ j : s ∈ V̄k[i]e⟨Xv ⌢ r⟩(eq. 10.3 v 0.7.0)
func verifyVerdictSignatures(currentTimeslot jamtime.Timeslot, verdict block.Verdict, currentValidators, archivedValidators safrole.ValidatorsData) error {
	currentEpoch := currentTimeslot.ToEpoch()
	validatorSet := currentValidators
	if verdict.EpochIndex != currentEpoch {
		validatorSet = archivedValidators
	}

	for _, judgment := range verdict.Judgements {
		context := state.SignatureContextValid
		if !judgment.IsValid {
			context = state.SignatureContextInvalid
		}

		message := append([]byte(context), verdict.ReportHash[:]...)

		if !ed25519.Verify(validatorSet[judgment.ValidatorIndex].Ed25519, message, judgment.Signature[:]) {
			return errors.New("bad signature")
		}
	}

	return nil
}

// isValidatorKeyInCurrentOrPrevEpoch checks if a validator's Ed25519 key exists in either
// the current or previous epoch's validator set.
// Equations 10.3, 10.5, 10.6(v0.7.0):
// - κ represents the current epoch's validator keys (active validator set)
// - λ represents the previous epoch's validator keys (archived validator set)
// - Valid signatures must come from validators in κ = {ke | k ∈ λ ∪ κ} ∖ ψo
// This check is used to validate that judgments, faults, and culprits come from
// validators who were active in either the current or previous epoch.
func isValidatorKeyInCurrentOrPrevEpoch(key ed25519.PublicKey, currentValidators, archivedValidators safrole.ValidatorsData) bool {
	// Check in current validators
	for _, validator := range currentValidators {
		if bytes.Equal(validator.Ed25519, key) {
			return true
		}
	}
	// Check in archived validators
	for _, validator := range archivedValidators {
		if bytes.Equal(validator.Ed25519, key) {
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

// CountPositiveJudgements counts the number of positive judgments in a verdict
func CountPositiveJudgements(v block.Verdict) uint16 {
	count := uint16(0)
	for _, judgment := range v.Judgements {
		if judgment.IsValid {
			count++
		}
	}
	return count
}

// validateFault validates a fault proof
// ∀(r,v,f,s) ∈ EF : ⋀{r ∈ ψ'B ⇔ r ∉ ψ'G ⇔ v, k ∈ k, s ∈ V̄f⟨Xv ⌢ r⟩} (eq. 10.6 v 0.7.0)
func validateFault(fault block.Fault, verdictSummaries []block.VerdictSummary, offendingValidators []ed25519.PublicKey) error {
	var summary block.VerdictSummary
	for _, v := range verdictSummaries {
		if v.ReportHash == fault.ReportHash {
			summary = v
			break
		}
	}

	// Fault vote should be opposite to verdict
	// If verdict is all positive, fault vote should be false
	if fault.IsValid && summary.VoteCount == DisputeVoteGood {
		return errors.New("fault verdict wrong")
	}
	// If verdict is all negative, fault vote should be true
	if !fault.IsValid && summary.VoteCount == DisputeVoteBad {
		return errors.New("fault verdict wrong")
	}

	// Cannot have faults for wonky verdicts - there's no clear "wrong" side
	if summary.VoteCount == DisputeVoteWonky {
		return errors.New("fault verdict wrong")
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

	if containsKey(offendingValidators, fault.ValidatorEd25519PublicKey) {
		return errors.New("offender already reported")
	}

	return nil
}

// validateCulprit validates a culprit
// ∀(r,f,s) ∈ EC : ⋀{r ∈ ψ'B, f ∈ k, s ∈ V̄f⟨XG ⌢ r⟩} (eq. 10.5 v 0.7.0)
func validateCulprit(culprit block.Culprit, badReports []crypto.Hash, offendingValidators []ed25519.PublicKey) error {
	// Must be in bad reports
	if !slices.Contains(badReports, culprit.ReportHash) {
		return errors.New("culprits verdict not bad")
	}

	// Verify guarantee signature
	message := append([]byte(state.SignatureContextGuarantee), culprit.ReportHash[:]...)
	if !ed25519.Verify(culprit.ValidatorEd25519PublicKey, message, culprit.Signature[:]) {
		return errors.New("bad signature")
	}

	if containsKey(offendingValidators, culprit.ValidatorEd25519PublicKey) {
		return errors.New("offender already reported")
	}

	return nil
}

// verifySortedUnique verifies the ordering and uniqueness constraints for disputes extrinsic
// Equations 10.7, 10.8, 10.10(v0.7.0):
// - Equation 10.7: EV = [(r,a,j) ∈ EV_r] (verdicts ordered by report hash)
// - Equation 10.8: EC = [(r,f,s) ∈ EC_f], EF = [(r,v,f,s) ∈ EF_f] (culprits and faults ordered by Ed25519 key)
// - Equation 10.10: ∀(r,a,j) ∈ EV : j = [(v,i,s) ∈ j_i] (judgments ordered by validator index)
// All sequences must be strictly ordered with no duplicates to ensure deterministic processing
func verifySortedUnique(disputes block.DisputeExtrinsic) error {
	// Check faults are sorted unique
	for i := 1; i < len(disputes.Faults); i++ {
		if bytes.Compare(disputes.Faults[i-1].ValidatorEd25519PublicKey, disputes.Faults[i].ValidatorEd25519PublicKey) >= 0 {
			return errors.New("faults not sorted unique")
		}
	}
	// Check culprits are sorted unique
	for i := 1; i < len(disputes.Culprits); i++ {
		if bytes.Compare(disputes.Culprits[i-1].ValidatorEd25519PublicKey, disputes.Culprits[i].ValidatorEd25519PublicKey) >= 0 {
			return errors.New("culprits not sorted unique")
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

// verifyNotAlreadyJudged ensures a verdict's report hasn't already been judged
// {r | (r,a,j) ∈ EV} ⫰ ψG ∪ ψB ∪ ψW (eq. 10.9 v 0.7.0)
func verifyNotAlreadyJudged(verdict block.Verdict, stateJudgements state.Judgements) error {
	reportHash := verdict.ReportHash
	if slices.Contains(stateJudgements.GoodWorkReports, reportHash) ||
		slices.Contains(stateJudgements.BadWorkReports, reportHash) ||
		slices.Contains(stateJudgements.WonkyWorkReports, reportHash) {
		return errors.New("already judged")
	}
	return nil
}

// validateVerdictAndComputeVerdictSummary implements the verdict validation and produces "v" verdict summary:
// - Equation 10.11: v ∈ ⟦(H, {0, ⌊1/3V⌋, ⌊2/3V⌋ + 1})⟧ (valid vote counts)
// - Equation 10.12: v = [(r, Σ(v,i,s)∈j v) | (r,a,j) <- EV] (sum positive judgments)
// - Equation 10.13: ∀(r, ⌊2/3V⌋ + 1) ∈ v : ∃(r, ...) ∈ EF (good verdicts need faults)
// - Equation 10.14: ∀(r, 0) ∈ v : |{(r, ...) ∈ EC}| ≥ 2 (bad verdicts need 2+ culprits)
// The function validates that:
// 1. All validator indices are valid
// 2. The vote count matches one of three valid thresholds (good/bad/wonky)
// 3. Good verdicts have at least one fault entry
// 4. Bad verdicts have at least two culprit entries
func validateVerdictAndComputeVerdictSummary(v block.Verdict, faults []block.Fault, culprits []block.Culprit) (block.VerdictSummary, error) {
	for _, j := range v.Judgements {
		if j.ValidatorIndex >= common.NumberOfValidators {
			return block.VerdictSummary{}, errors.New("invalid validator index")
		}
	}
	positiveVotes := CountPositiveJudgements(v)

	switch positiveVotes {
	case DisputeVoteGood:
		validFaults := 0
		for _, fault := range faults {
			if fault.ReportHash != v.ReportHash || fault.IsValid {
				continue
			}
			validFaults++
		}
		if validFaults == 0 {
			return block.VerdictSummary{}, errors.New("not enough faults")
		}
	case DisputeVoteBad:
		matchingCulprits := 0
		for _, c := range culprits {
			if c.ReportHash == v.ReportHash {
				matchingCulprits++
			}
		}
		if matchingCulprits < 2 {
			return block.VerdictSummary{}, errors.New("not enough culprits")
		}
	case DisputeVoteWonky:
		// Wonky verdicts are valid and should be processed
	default:
		return block.VerdictSummary{}, errors.New("bad vote split")
	}

	return block.VerdictSummary{
		ReportHash: v.ReportHash,
		VoteCount:  positiveVotes,
	}, nil
}

// ValidateDisputesExtrinsicAndProduceJudgements processes the disputes extrinsic from a block,
// validates all verdicts, faults, and culprits, and produces an updated judgements state.
//
// The disputes system allows validators to collectively judge work-reports as good, bad, or wonky
// (undecidable). It also tracks misbehaving validators who either guaranteed invalid reports
// (culprits) or made incorrect judgments (faults).
//
// This function ensures all dispute data is valid before updating the on-chain record of
// judgements and offending validators.
func ValidateDisputesExtrinsicAndProduceJudgements(prevTimeslot jamtime.Timeslot, disputes block.DisputeExtrinsic, validators validator.ValidatorState, stateJudgements state.Judgements) (state.Judgements, error) {
	// First, verify that all items in the extrinsic are properly sorted and unique.
	// This ensures deterministic processing and prevents duplicate entries.
	if err := verifySortedUnique(disputes); err != nil {
		return state.Judgements{}, err
	}
	// Prepare to collect verdict summaries and track new offending validators
	summs := make([]block.VerdictSummary, 0, len(disputes.Verdicts))
	newOffenders := []ed25519.PublicKey{}

	// Clone the existing judgements state to build upon it
	newJudgements := state.Judgements{
		GoodWorkReports:     slices.Clone(stateJudgements.GoodWorkReports),
		BadWorkReports:      slices.Clone(stateJudgements.BadWorkReports),
		WonkyWorkReports:    slices.Clone(stateJudgements.WonkyWorkReports),
		OffendingValidators: slices.Clone(stateJudgements.OffendingValidators),
	}

	// Process each verdict in the disputes extrinsic
	for _, v := range disputes.Verdicts {
		// Verify the verdict is from the current or previous epoch only.
		// Verdicts from future epochs are invalid, and verdicts older than
		// one epoch are considered stale and rejected.
		if v.EpochIndex > prevTimeslot.ToEpoch() {
			return state.Judgements{}, errors.New("bad judgement age")
		}
		if prevTimeslot.ToEpoch()-v.EpochIndex > 1 {
			return state.Judgements{}, errors.New("bad judgement age")
		}

		// Validate the verdict structure and compute its summary (vote count).
		// This checks that the verdict has the required number of judgments
		// (2/3+1 for good, 0 for bad, 1/3 for wonky) and validates related
		// fault/culprit requirements.
		verdictSummary, err := validateVerdictAndComputeVerdictSummary(v, disputes.Faults, disputes.Culprits)
		if err != nil {
			return state.Judgements{}, err
		}
		// Ensure this work-report hasn't already been judged.
		// Once a report is judged as good, bad, or wonky, it cannot be re-judged.
		if err := verifyNotAlreadyJudged(v, stateJudgements); err != nil {
			return state.Judgements{}, err
		}
		// Verify all judgment signatures in the verdict are valid and from
		// validators in the appropriate epoch's validator set.
		if err := verifyVerdictSignatures(prevTimeslot, v, validators.CurrentValidators, validators.ArchivedValidators); err != nil {
			return state.Judgements{}, err
		}
		summs = append(summs, verdictSummary)
	}

	// Categorize each verdict's report hash based on the vote outcome
	for _, s := range summs {
		switch s.VoteCount {
		case DisputeVoteGood:
			newJudgements.GoodWorkReports = append(newJudgements.GoodWorkReports, s.ReportHash)
		case DisputeVoteBad:
			newJudgements.BadWorkReports = append(newJudgements.BadWorkReports, s.ReportHash)
		case DisputeVoteWonky:
			newJudgements.WonkyWorkReports = append(newJudgements.WonkyWorkReports, s.ReportHash)
		default:
			return state.Judgements{}, errors.New("bad vote split")
		}
	}

	// Process culprits - validators who guaranteed work-reports that were judged as bad.
	// These validators signed guarantees for invalid work, which is a punishable offense.
	for _, c := range disputes.Culprits {
		// Verify the culprit's guarantee signature and ensure the report was judged bad
		if err := validateCulprit(c, newJudgements.BadWorkReports, stateJudgements.OffendingValidators); err != nil {
			return state.Judgements{}, err
		}
		// Ensure the culprit was a validator in the current or previous epoch
		if !isValidatorKeyInCurrentOrPrevEpoch(c.ValidatorEd25519PublicKey, validators.CurrentValidators, validators.ArchivedValidators) {
			return state.Judgements{}, errors.New("bad guarantor key")
		}
		// Add to new offenders list
		newOffenders = append(newOffenders, c.ValidatorEd25519PublicKey)
	}

	// Process faults - validators who made judgments that contradict the verdict.
	for _, f := range disputes.Faults {
		// Verify the fault's judgment signature and ensure it contradicts the verdict
		if err := validateFault(f, summs, stateJudgements.OffendingValidators); err != nil {
			return state.Judgements{}, err
		}
		// Ensure the faulty validator was active in the current or previous epoch
		if !isValidatorKeyInCurrentOrPrevEpoch(f.ValidatorEd25519PublicKey, validators.CurrentValidators, validators.ArchivedValidators) {
			return state.Judgements{}, errors.New("bad auditor key")
		}
		// Add to new offenders list
		newOffenders = append(newOffenders, f.ValidatorEd25519PublicKey)
	}
	// Add all newly identified offending validators to the permanent record
	newJudgements.OffendingValidators = append(newJudgements.OffendingValidators, newOffenders...)

	return newJudgements, nil
}
