package block

import (
	"crypto/ed25519"
	"github.com/eigerco/strawberry/internal/common"
	"github.com/eigerco/strawberry/internal/crypto"
)

const ValidatorsSuperMajority = (2 * common.NumberOfValidators / 3) + 1 // 2/3V + 1

type DisputeExtrinsic struct {
	Verdicts []Verdict
	Culprits []Culprit
	Faults   []Fault
}

type Verdict struct {
	ReportHash crypto.Hash                       // H, hash of the work report
	EpochIndex uint32                            // ⌊τ/E⌋ - N2, epoch index
	Judgements  [ValidatorsSuperMajority]Judgement // ⟦{⊺,⊥},NV,E⟧⌊2/3V⌋+1
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
