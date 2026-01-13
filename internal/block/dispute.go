package block

import (
	"github.com/eigerco/strawberry/internal/constants"
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/crypto/ed25519"
	"github.com/eigerco/strawberry/internal/jamtime"
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
// ED ≡ {EV, EC, EF}
// where EV ∈ ⟦{H, ⌊τ/E⌋ - N2, ⟦{{⊺,⊥}, NV, V̄}⟧⌊2/3V⌋+1}⟧
// and EC ∈ ⟦{H, H̄, V̄}⟧,
// EF ∈ ⟦{H, {⊺,⊥}, H̄, V̄}⟧ (eq. 10.2 v 0.7.0)
type DisputeExtrinsic struct {
	Verdicts []Verdict // Final judgments on work-reports backed by ≥ 2/3 validator signatures
	Culprits []Culprit // Guarantors of invalid work-reports
	Faults   []Fault   // Auditors whose judgments were inconsistent with the final verdict
}

// Verdict represents a collection of judgments made by validators on a work report.
// It includes the report hash, epoch index, and a super-majority of judgments.
type Verdict struct {
	ReportHash crypto.Hash                                  // H, hash of the work report
	EpochIndex jamtime.Epoch                                // ⌊τ/E⌋ - N2 (current or prev), epoch index
	Judgements [constants.ValidatorsSuperMajority]Judgement // ⟦{{⊺,⊥}, NV, V̄}⟧⌊2/3V⌋+1
}

// Culprit represents misbehaving guarantor who guaranteed an invalid work-report
type Culprit struct {
	ReportHash                crypto.Hash             // H, hash of the work report
	ValidatorEd25519PublicKey ed25519.PublicKey       // H̄
	Signature                 crypto.Ed25519Signature // V̄
}

// Fault is an Auditor who made incorrect judgment
type Fault struct {
	ReportHash                crypto.Hash             // H, hash of the work report
	IsValid                   bool                    // {⊺,⊥}
	ValidatorEd25519PublicKey ed25519.PublicKey       // H̄
	Signature                 crypto.Ed25519Signature // V̄
}

// Judgement is a statement from an auditor that declares whether a given work-report is valid or invalid
type Judgement struct {
	IsValid        bool                    // {⊺,⊥}
	ValidatorIndex uint16                  // NV
	Signature      crypto.Ed25519Signature // V̄
}

// VerdictSummary V is a sequence of (report_hash, vote_count) pairs
// where vote_count must be exactly one of: 0, ⌊V/3⌋, or ⌊2V/3⌋+1
// V ∈ ⟦⟨H, {0, ⌊1/3V⌋, ⌊2/3V⌋ + 1}⟩⟧ (eq. 10.11 v0.7.0)
type VerdictSummary struct {
	ReportHash crypto.Hash // H
	VoteCount  uint16      // Must be 0, V/3, or 2V/3+1
}
