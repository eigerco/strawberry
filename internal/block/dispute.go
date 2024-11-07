package block

import (
	"crypto/ed25519"
	"github.com/eigerco/strawberry/internal/common"
	"github.com/eigerco/strawberry/internal/crypto"
)

type DisputeExtrinsic struct {
	Verdicts []Verdict
	Culprits []Culprit
	Faults   []Fault
}

type Verdict struct {
	ReportHash crypto.Hash                               // H, hash of the work report
	EpochIndex uint32                                    // ⌊τ/E⌋ - N2, epoch index
	Judgements [common.ValidatorsSuperMajority]Judgement // ⟦{⊺,⊥},NV,E⟧⌊2/3V⌋+1
}

type Culprit struct {
	ReportHash                crypto.Hash             // H, hash of the work report
	ValidatorEd25519PublicKey ed25519.PublicKey       // He
	Signature                 crypto.Ed25519Signature // E
}

type Fault struct {
	ReportHash                crypto.Hash             // H, hash of the work report
	IsValid                   bool                    // {⊺,⊥}
	ValidatorEd25519PublicKey ed25519.PublicKey       // He
	Signature                 crypto.Ed25519Signature // E
}

// Judgement represents a single judgment with a signature
type Judgement struct {
	IsValid        bool                    // v: {⊺,⊥}
	ValidatorIndex uint16                  // i: NV
	Signature      crypto.Ed25519Signature // s: E
}

// CountPositiveJudgments counts the number of positive judgments in a verdict
func CountPositiveJudgments(judgments [common.ValidatorsSuperMajority]Judgement) int {
	count := 0
	for _, judgment := range judgments {
		if judgment.IsValid {
			count++
		}
	}
	return count
}
