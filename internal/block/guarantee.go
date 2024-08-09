package block

import (
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/jamtime"
)

// GuaranteesExtrinsic represents the E_G extrinsic
type GuaranteesExtrinsic struct {
	Guarantees []Guarantee
}

// Guarantee represents a single guarantee within the E_G extrinsic
type Guarantee struct {
	WorkReport  WorkReport            // The work report being guaranteed
	Credentials []CredentialSignature // The credentials proving the guarantee's validity
	Timeslot    jamtime.Timeslot      // The timeslot when this guarantee was made
}

// CredentialSignature represents a single signature within the credential
type CredentialSignature struct {
	ValidatorIndex uint32                            // Index of the validator providing this signature
	Signature      [crypto.Ed25519SignatureSize]byte // The Ed25519 signature
}

// WorkReport represents a work report in the JAM state
// TODO: The total serialized size of a work-report may be no greater than MaxWorkPackageSizeBytes.
type WorkReport struct {
	WorkPackageSpecification WorkPackageSpecification // Work-package specification (s)
	RefinementContext        RefinementContext        // Refinement context (x)
	CoreIndex                uint16                   // Core index (c) - Max value: TotalNumberOfCores
	AuthorizerHash           crypto.Hash              // HeaderHash of the authorizer (a)
	Output                   []byte                   // Output of the work report (o)
	WorkResults              []WorkResult             // Results of the evaluation of each of the items in the work-package (r) - Min value: MinWorkPackageResultsSize. Max value: MaxWorkPackageResultsSize.
}

type WorkPackageSpecification struct {
	WorkPackageHash           crypto.Hash // Hash of the work-package (h)
	AuditableWorkBundleLength uint32      // Length of the auditable work bundle (l)
	ErasureRoot               crypto.Hash // Erasure root (u) - is the root of a binary Merkle tree which functions as a commitment to all data required for the auditing of the report and for use by later workpackages should they need to retrieve any data yielded. It is thus used by assurers to verify the correctness of data they have been sent by guarantors, and it is later verified as correct by auditors.
	SegmentRoot               crypto.Hash // Segment root (e) - root of a constant-depth, left-biased and zero-hash-padded binary Merkle tree committing to the hashes of each of the exported segments of each work-item. These are used by guarantors to verify the correctness of any reconstructed segments they are called upon to import for evaluation of some later work-package.
}

// RefinementContext describes the context of the chain at the point that the report’s corresponding work-package was evaluated.
type RefinementContext struct {
	Anchor                  RefinementContextAnchor       // Historical block anchor
	LookupAnchor            RefinementContextLookupAnchor // Historical block anchor
	PrerequisiteWorkPackage *crypto.Hash                  // Prerequisite work package (p) (optional)
}

type RefinementContextAnchor struct {
	HeaderHash         crypto.Hash // HeaderHash of the anchor (a)
	PosteriorStateRoot crypto.Hash // Posterior state root (s)
	PosteriorBeefyRoot crypto.Hash // Posterior beefy root (b)
}

type RefinementContextLookupAnchor struct {
	HeaderHash crypto.Hash   // HeaderHash of the anchor (l)
	Timeslot   jamtime.Timeslot // Timeslot (t)
}

// WorkResultError represents the type of error that occurred during work execution
type WorkResultError int

const (
	NoError               WorkResultError = iota // Represents no error, successful execution
	OutOfGas                                     // Out-of-gas error
	UnexpectedTermination                        // Unexpected program termination.
	CodeNotAvailable                             // The service’s code was not available for lookup in state at the posterior state of the lookup-anchor block.
	CodeTooLarge                                 // The code was available but was beyond the maximum size allowed S.
)

type ServiceId [32]byte

// WorkResult is the data conduit by which services’ states may be altered through the computation done within a work-package.
type WorkResult struct {
	ServiceId              ServiceId        // Service ID (s) - The index of the service whose state is to be altered and thus whose refine code was already executed.
	ServiceHashCode        crypto.Hash      // Hash of the service code (c) - The hash of the code of the service at the time of being reported.
	PayloadHash            crypto.Hash      // Hash of the payload (l) - The hash of the payload within the work item which was executed in the refine stage to give this result. Provided to the accumulation logic of the service later on.
	GasPrioritizationRatio uint64           // Gas prioritization ratio (g) - used when determining how much gas should be allocated to execute of this item’s accumulate.
	Output                 WorkResultOutput // Output of the work result (o) ∈ Y ∪ J: Output or error (Y is the set of octet strings, J is the set of work execution errors)
}

// WorkResultOutput represents either the successful output or an error from a work result
type WorkResultOutput struct {
	Data  []byte          // Represents successful output (Y)
	Error WorkResultError // Represents error output (J)
}

// IsSuccessful checks if the work result is successful
func (wr WorkResult) IsSuccessful() bool {
	return wr.Output.Error == NoError
}

// NewSuccessfulWorkResult creates a new successful WorkResult
func NewSuccessfulWorkResult(serviceId ServiceId, serviceHashCode, payloadHash crypto.Hash, gasPrioritizationRatio uint64, output []byte) WorkResult {
	return WorkResult{
		ServiceId:              serviceId,
		ServiceHashCode:        serviceHashCode,
		PayloadHash:            payloadHash,
		GasPrioritizationRatio: gasPrioritizationRatio,
		Output:                 WorkResultOutput{Data: output, Error: NoError},
	}
}

// NewErrorWorkResult creates a new error WorkResult
func NewErrorWorkResult(serviceId ServiceId, serviceHashCode, payloadHash crypto.Hash, gasPrioritizationRatio uint64, errorResult WorkResultError) WorkResult {
	return WorkResult{
		ServiceId:              serviceId,
		ServiceHashCode:        serviceHashCode,
		PayloadHash:            payloadHash,
		GasPrioritizationRatio: gasPrioritizationRatio,
		Output:                 WorkResultOutput{Data: nil, Error: errorResult},
	}
}
