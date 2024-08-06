package block

import (
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/time"
)

// WorkResultError represents the type of error that occurred during work execution
type WorkResultError int

// WorkResultError represents the possible errors for a work result
const (
	NoError      WorkResultError = iota
	OutOfGas                     // ∞: Out of gas error
	Panic                        // ☇: Panic error
	BadCode                      // BAD: Service's code not available
	CodeTooLarge                 // BIG: Code available but exceeds maximum size
)

// GuaranteesExtrinsic represents the E_G extrinsic
type GuaranteesExtrinsic struct {
	Guarantees []Guarantee
}

// Guarantee represents a single guarantee within the E_G extrinsic
type Guarantee struct {
	WorkReport  WorkReport            // The work report being guaranteed
	Credentials []CredentialSignature // The credentials proving the guarantee's validity
	Timeslot    time.Timeslot         // The timeslot when this guarantee was made
}

// CredentialSignature represents a single signature within the credential
type CredentialSignature struct {
	ValidatorIndex uint32                            // Index of the validator providing this signature
	Signature      [crypto.Ed25519SignatureSize]byte // The Ed25519 signature
}

// WorkReport represents a report of completed work
type WorkReport struct {
	Specification  WorkPackageSpecification
	Context        RefinementContext
	CoreIndex      uint16       // N_C
	AuthorizerHash crypto.Hash  // H
	Output         []byte       // Y a set of octet strings
	Results        []WorkResult // r ∈ ⟦L⟧_1:I: Sequence of 1 to I work results
}

// WorkPackageSpecification defines the specification of a work package
type WorkPackageSpecification struct {
	Hash        crypto.Hash // h ∈ H: Work package hash
	Length      uint32      // l ∈ N_L: Auditable work bundle length (N_L is the set of blob length values)
	ErasureRoot crypto.Hash // u ∈ H: Erasure root
	SegmentRoot crypto.Hash // e ∈ H: Segment root
}

// RefinementContext provides context for the refinement process
type RefinementContext struct {
	AnchorHeaderHash         crypto.Hash   // a ∈ H: Anchor header hash
	AnchorPosteriorStateRoot crypto.Hash   // s ∈ H: Anchor state root
	AnchorPosteriorBeefyRoot crypto.Hash   // b ∈ H: Anchor Beefy root
	LookupAnchorHeaderHash   crypto.Hash   // l ∈ H: Lookup anchor hash
	LookupAnchorTimeslot     time.Timeslot // t ∈ N_T: Lookup anchor timeslot
	PrerequisiteHash         *crypto.Hash  // p ∈ H?: Optional prerequisite work package hash
}

// WorkResult represents the result of a single work item
type WorkResult struct {
	ServiceIndex uint32           // s ∈ N_S: Service index (N_S is the set of service indices)
	CodeHash     crypto.Hash      // c ∈ H: Code hash
	PayloadHash  crypto.Hash      // l ∈ H: Payload hash
	GasRatio     uint64           // g ∈ N_G: Gas prioritization ratio
	Output       WorkResultOutput // o ∈ Y ∪ J: Output or error (Y is the set of octet strings, J is the set of work execution errors)
}

// WorkResultOutput represents either the successful output or an error from a work result
type WorkResultOutput struct {
	Data  []byte          // Represents successful output (Y)
	Error WorkResultError // Represents error output (J)
}
