package block

import (
	"github.com/eigerco/strawberry/internal/crypto"
)

type DisputeExtrinsic struct {
	Verdicts []Verdict
	Culprits []Culprit
	Faults   []Fault
}

type Verdict struct {
	ReportHash crypto.Hash // H, hash of the work report
	EpochIndex uint32      // ⌊τ/E⌋ - N2, epoch index
	Judgments  []Judgment  // ⟦{⊺,⊥},NV,E⟧⌊2/3V⌋+1
}

type Culprit struct {
	ReportHash                crypto.Hash                       // H, hash of the work report
	ValidatorEd25519PublicKey crypto.Ed25519PublicKey           // He
	Signature                 [crypto.Ed25519SignatureSize]byte // E
}

type Fault struct {
	ReportHash                crypto.Hash                       // H, hash of the work report
	IsValid                   bool                              // {⊺,⊥}
	ValidatorEd25519PublicKey crypto.Ed25519PublicKey           // He
	Signature                 [crypto.Ed25519SignatureSize]byte // E
}

// Judgment represents a single judgment with a signature
type Judgment struct {
	IsValid        bool                              // v: {⊺,⊥}
	ValidatorIndex uint16                            // i: NV
	Signature      [crypto.Ed25519SignatureSize]byte // s: E
}