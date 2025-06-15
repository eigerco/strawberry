package block

import (
	"crypto/ed25519"

	"github.com/eigerco/strawberry/internal/common"
	"github.com/eigerco/strawberry/internal/crypto"
)

// DisputeExtrinsic represents the structured input for submitting disputes.
//
// This extrinsic is used to finalize the outcome of disputes over work-report validity.
// It includes:
//   - Verdicts: Aggregated judgments from auditors determining whether a work-report is valid.
//   - Culprits: Validators who guaranteed work-reports later found to be invalid.
//   - Faults: Auditors who issued judgments that contradict the finalized verdict.
//
// This extrinsic is included in a block and updates on-chain state:
//   - Registers final verdicts (valid, invalid, or inconclusive) for specific work-reports.
//   - Flags misbehaving validators.
//
// Equation 10.2(v0.6.7):
// E_D ≡ (v, c, f)
// where v ∈ ⟦{H, ⌊τ/E⌋ - N_2, ⟦{⊺, ⊥}, N_V, E⟧_⌊2/3V⌋+1}⟧
// and c ∈ ⟦⟨H, H_E, E⟩⟧ , f ∈ ⟦⟨H, {⊺, ⊥}, H_E, E⟩⟧
type DisputeExtrinsic struct {
	Verdicts []Verdict // Final judgments on work-reports backed by ≥ 2/3 validator signatures
	Culprits []Culprit // Guarantors of invalid work-reports
	Faults   []Fault   // Auditors whose judgments were inconsistent with the final verdict
}

// Verdict represents a collection of judgments made by validators on a work report.
// It includes the report hash, epoch index, and a super-majority of judgments.
type Verdict struct {
	ReportHash crypto.Hash                               // H, hash of the work report
	EpochIndex uint32                                    // ⌊τ/E⌋ - N2 (current or prev), epoch index
	Judgements [common.ValidatorsSuperMajority]Judgement // ⟦{⊺,⊥},NV,E⟧⌊2/3V⌋+1
}

// Culprit represents misbehaving guarantor who guaranteed an invalid work-report
type Culprit struct {
	ReportHash                crypto.Hash             // H, hash of the work report
	ValidatorEd25519PublicKey ed25519.PublicKey       // He
	Signature                 crypto.Ed25519Signature // E
}

// Auditor who made incorrect judgment
type Fault struct {
	ReportHash                crypto.Hash             // H, hash of the work report
	IsValid                   bool                    // {⊺,⊥}
	ValidatorEd25519PublicKey ed25519.PublicKey       // He
	Signature                 crypto.Ed25519Signature // E
}

// Judgement is a statement from an auditor that declares whether a given work-report is valid or invalid
type Judgement struct {
	IsValid        bool                    // v: {⊺,⊥}
	ValidatorIndex uint16                  // i: NV
	Signature      crypto.Ed25519Signature // s: E
}

// Equation 10.11(v0.6.7): V is a sequence of (report_hash, vote_count) pairs
// where vote_count must be exactly one of: 0, ⌊V/3⌋, or ⌊2V/3⌋+1
// V ∈ ⟦⟨H, {0, ⌊1/3V⌋, ⌊2/3V⌋ + 1}⟩⟧
type VerdictSummary struct {
	ReportHash crypto.Hash // H
	VoteCount  uint16      // Must be 0, V/3, or 2V/3+1
}
