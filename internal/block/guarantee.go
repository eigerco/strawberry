package block

import (
	ed25519 "crypto/ed25519"
	"fmt"

	"github.com/eigerco/strawberry/internal/common"
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/jamtime"
	"github.com/eigerco/strawberry/pkg/serialization/codec/jam"
)

// GuaranteesExtrinsic represents the E_G extrinsic
// EG ∈ ⟦{r ∈ R, t ∈ NT, a ∈ ⟦{NV, V̄}⟧2:3}⟧:C (eq. 11.23 v 0.7.0)
type GuaranteesExtrinsic struct {
	Guarantees []Guarantee
}

// Guarantee represents a single guarantee within the E_G extrinsic
type Guarantee struct {
	WorkReport  WorkReport            // The work report being guaranteed
	Timeslot    jamtime.Timeslot      // The timeslot when this guarantee was made
	Credentials []CredentialSignature // The credentials proving the guarantee's validity
}

// CredentialSignature represents a single signature within the credential
type CredentialSignature struct {
	ValidatorIndex uint16                  // Index of the validator providing this signature
	Signature      crypto.Ed25519Signature // The Ed25519 signature
}

// WorkReport represents a work report in the JAM state
// R ≡ {s ∈ Y, c ∈ C, c ∈ NC, a ∈ H, t ∈ B, l ∈ ⟦H → H⟧, d ∈ ⟦D⟧1:I, g ∈ NG} (eq. 11.2 v 0.7.0)
// E(rs, rc, rc, ra, rg , ↕rt, ↕rl, ↕rd)
type WorkReport struct {
	AvailabilitySpecification AvailabilitySpecification   // Availability specification (s)
	RefinementContext         RefinementContext           // Refinement context (c)(c bold)
	CoreIndex                 uint16                      `jam:"encoding=compact"` // Core index (c) - Max value: TotalNumberOfCores
	AuthorizerHash            crypto.Hash                 // HeaderHash of the authorizer (a)
	AuthGasUsed               uint64                      `jam:"encoding=compact"` // The amount of gas used during authorization (g)
	AuthorizerTrace           []byte                      // Trace from Is-Authorized invocation (t)
	SegmentRootLookup         map[crypto.Hash]crypto.Hash // A segment-root lookup dictionary (l ∈ ⟨H → H⟩)
	WorkDigests               []WorkDigest                // Results of the evaluation of each of the items in the work-package (d) - Min value: MinWorkPackageResultsSize. Max value: MaxWorkPackageResultsSize.
}

// AvailabilitySpecification represents // Y ≡ {p ∈ H, l ∈ NL, u ∈ H, e ∈ H, n ∈ N} (eq. 11.5 v 0.7.0)
type AvailabilitySpecification struct {
	WorkPackageHash           crypto.Hash // Hash of the work-package (p)
	AuditableWorkBundleLength uint32      // Length of the auditable work bundle (l)
	ErasureRoot               crypto.Hash // Erasure root (u) - is the root of a binary Merkle tree which functions as a commitment to all data required for the auditing of the report and for use by later workpackages should they need to retrieve any data yielded. It is thus used by assurers to verify the correctness of data they have been sent by guarantors, and it is later verified as correct by auditors.
	SegmentRoot               crypto.Hash // Segment root (e) - root of a constant-depth, left-biased and zero-hash-padded binary Merkle tree committing to the hashes of each of the exported segments of each work-item. These are used by guarantors to verify the correctness of any reconstructed segments they are called upon to import for evaluation of some later work-package.
	SegmentCount              uint16      // Segment count (n)
}

// RefinementContext describes the context of the chain at the point that the report's corresponding work-package was evaluated.
//
//	C ≡ {a ∈ H, s ∈ H, b ∈ H, l ∈ H, t ∈ NT, p ∈ {[H]}} (eq. 11.4 v 0.7.0)
type RefinementContext struct {
	Anchor                  RefinementContextAnchor       // Historical block anchor
	LookupAnchor            RefinementContextLookupAnchor // Historical block anchor
	PrerequisiteWorkPackage []crypto.Hash                 // Prerequisite work package p ∈ {[H]}
}

// a ∈ H, s ∈ H, b ∈ H
type RefinementContextAnchor struct {
	HeaderHash         crypto.Hash // HeaderHash of the anchor (a)
	PosteriorStateRoot crypto.Hash // Posterior state root (s)
	PosteriorBeefyRoot crypto.Hash // Posterior beefy root (b)
}

// l ∈ H, t ∈ N_T
type RefinementContextLookupAnchor struct {
	HeaderHash crypto.Hash      // HeaderHash of the anchor (l)
	Timeslot   jamtime.Timeslot // Timeslot (t)
}

// GuarantorAssignments represents the mapping of validators to cores and their keys
// M ∈ {⟦NC⟧V, ⟦H̄⟧V} (eq. 11.18 v 0.7.0)
type GuarantorAssignments struct {
	CoreAssignments [common.NumberOfValidators]uint16            // Core index for each validator
	ValidatorKeys   [common.NumberOfValidators]ed25519.PublicKey // Ed25519 public key for each validator
}

// WorkResultError represents the type of error that occurred during work execution
type WorkResultError uint8

const (
	NoError                 WorkResultError = iota // Represents no error, successful execution
	OutOfGas                                       // ∞ Out-of-gas error
	UnexpectedTermination                          // ☇ Unexpected program termination.
	InvalidNumberOfExports                         // ⊚ The number of exports made was invalidly reported
	DigestSizeLimitExceeded                        // ⊖ Digest size limit exceeded
	CodeNotAvailable                               // BAD The service’s code was not available for lookup in state at the posterior state of the lookup-anchor block.
	CodeTooLarge                                   // BIG The code was available but was beyond the maximum size allowed WC.
)

type ServiceId uint32

// WorkDigest is the data conduit by which services' states may be altered through the computation done within a work-package.
// D ≡ {s ∈ NS, c ∈ H, y ∈ H, g ∈ NG, l ∈ B ∪ E, u ∈ NG, i ∈ N, x ∈ N, z ∈ N, e ∈ N}(eq. 11.6 v 0.7.0)
type WorkDigest struct {
	ServiceId             ServiceId               // Service ID (s) - The index of the service whose state is to be altered and thus whose refine code was already executed.
	ServiceHashCode       crypto.Hash             // Hash of the service code (c) - The hash of the code of the service at the time of being reported.
	PayloadHash           crypto.Hash             // Hash of the payload (y) - The hash of the payload within the work item which was executed in the refine stage to give this result. Provided to the accumulation logic of the service later on.
	GasLimit              uint64                  // Gas limit (g) - used when determining how much gas should be allocated to execute of this item's accumulate.
	Output                WorkResultOutputOrError // Output of the work result (l) ∈ B ∪ E: Output blob or error (B is the set of blobs/octet sequences, E is the set of work execution errors)
	GasUsed               uint64                  `jam:"encoding=compact"` // (u) the actual amount of gas used during refinement
	SegmentsImportedCount uint16                  `jam:"encoding=compact"` // (i) the number of segments imported from
	ExtrinsicCount        uint16                  `jam:"encoding=compact"` // (x) the number of the extrinsics used in computing the workload
	ExtrinsicSize         uint32                  `jam:"encoding=compact"` // (z) total size in octets of the extrinsics used in computing the workload
	SegmentsExportedCount uint16                  `jam:"encoding=compact"` // (e) the number of segments exported into
}

// WorkResultOutputOrError represents either the successful output or an error from a work result
type WorkResultOutputOrError struct {
	Inner any
}

func (wer *WorkResultOutputOrError) SetValue(value any) error {
	switch v := value.(type) {
	case []byte:
		wer.Inner = v
	case uint8:
		wer.Inner = WorkResultError(v)
	case WorkResultError:
		wer.Inner = v
	default:
		return fmt.Errorf(jam.ErrUnsupportedType, v)
	}

	return nil
}

func (wer WorkResultOutputOrError) IndexValue() (uint, any, error) {
	switch wer.Inner.(type) {
	case []byte:
		return 0, wer.Inner, nil
	case WorkResultError:
		return uint(wer.Inner.(WorkResultError)), nil, nil
	}

	return 0, nil, jam.ErrUnsupportedEnumTypeValue
}

func (wer WorkResultOutputOrError) ValueAt(index uint) (any, error) {
	switch index {
	case uint(NoError):
		return []byte{}, nil
	case uint(OutOfGas), uint(UnexpectedTermination), uint(InvalidNumberOfExports), uint(DigestSizeLimitExceeded), uint(CodeNotAvailable), uint(CodeTooLarge):
		return nil, nil
	}

	return nil, jam.ErrUnknownEnumTypeValue
}

// IsSuccessful checks if the work result is successful
func (wer WorkDigest) IsSuccessful() bool {
	if _, ok := wer.Output.Inner.([]byte); ok {
		return true
	}

	return false
}

// NewSuccessfulWorkResult creates a new successful WorkResult
func NewSuccessfulWorkResult(serviceID ServiceId, serviceHashCode, payloadHash crypto.Hash, gasPrioritizationRatio uint64, output []byte) WorkDigest {
	return WorkDigest{
		ServiceId:       serviceID,
		ServiceHashCode: serviceHashCode,
		PayloadHash:     payloadHash,
		GasLimit:        gasPrioritizationRatio,
		Output:          WorkResultOutputOrError{output},
	}
}

// NewErrorWorkResult creates a new error WorkResult
func NewErrorWorkResult(serviceID ServiceId, serviceHashCode, payloadHash crypto.Hash, gasPrioritizationRatio uint64, errorResult WorkResultError) WorkDigest {
	return WorkDigest{
		ServiceId:       serviceID,
		ServiceHashCode: serviceHashCode,
		PayloadHash:     payloadHash,
		GasLimit:        gasPrioritizationRatio,
		Output:          WorkResultOutputOrError{errorResult},
	}
}

func (w WorkReport) Hash() (crypto.Hash, error) {
	encodedData, err := w.Encode()
	if err != nil {
		return crypto.Hash{}, err
	}
	return crypto.HashData(encodedData), nil
}

func (w WorkReport) Encode() ([]byte, error) {
	encodedData, err := jam.Marshal(w)
	if err != nil {
		return []byte{}, err
	}
	return encodedData, nil
}

// ∀r ∈ R : |rt| + ∑d∈rd∩B |dl| ≤ WR (eq. 11.8 v 0.7.0)
func (w WorkReport) OutputSizeIsValid() bool {
	totalOutputSize := 0
	for _, result := range w.WorkDigests {
		if result.IsSuccessful() {
			totalOutputSize += len(result.Output.Inner.([]byte))
		}
	}
	totalOutputSize += len(w.AuthorizerTrace)

	return totalOutputSize <= common.MaxWorkPackageSizeBytes
}

// ∀r ∈ R : |rl| + |(rc)p| ≤ J (eq. 11.3 v 0.7.0)
func (w WorkReport) DependenciesCountIsValid() bool {
	segmentRootLookupCount := len(w.SegmentRootLookup)
	prerequisiteCount := len(w.RefinementContext.PrerequisiteWorkPackage)
	return segmentRootLookupCount+prerequisiteCount <= common.WorkReportMaxSumOfDependencies
}
