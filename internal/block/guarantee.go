package block

import (
	"encoding/json"
	"fmt"
	"github.com/ChainSafe/gossamer/pkg/scale"
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/jamtime"
	"github.com/eigerco/strawberry/pkg/serialization/codec/jam"
)

// GuaranteesExtrinsic represents the E_G extrinsic
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
	HeaderHash crypto.Hash      // HeaderHash of the anchor (l)
	Timeslot   jamtime.Timeslot // Timeslot (t)
}

const (
	NoError               jam.EnumError = iota // Represents no error, successful execution
	OutOfGas                                   // Out-of-gas error
	UnexpectedTermination                      // Unexpected program termination.
	CodeNotAvailable                           // The service’s code was not available for lookup in state at the posterior state of the lookup-anchor block.
	CodeTooLarge                               // The code was available but was beyond the maximum size allowed S.
)

//type WorkExecResult struct {
//	Ok           *[]byte // Represents the [0] ByteSequence option
//	OutOfGas     bool    // Represents the [1] NULL option
//	Panic        bool    // Represents the [2] NULL option
//	BadCode      bool    // Represents the [3] NULL option
//	CodeOversize bool    // Represents the [4] NULL option
//}

type ServiceId uint32

// WorkResult is the data conduit by which services’ states may be altered through the computation done within a work-package.
type WorkResult struct {
	ServiceId              ServiceId      // Service ID (s) - The index of the service whose state is to be altered and thus whose refine code was already executed.
	ServiceHashCode        crypto.Hash    // Hash of the service code (c) - The hash of the code of the service at the time of being reported.
	PayloadHash            crypto.Hash    // Hash of the payload (l) - The hash of the payload within the work item which was executed in the refine stage to give this result. Provided to the accumulation logic of the service later on.
	GasPrioritizationRatio uint64         // Gas prioritization ratio (g) - used when determining how much gas should be allocated to execute of this item’s accumulate.
	Output                 WorkExecResult // Output of the work result (o) ∈ Y ∪ J: Output or error (Y is the set of octet strings, J is the set of work execution errors)
}

// WorkResultOutput represents either the successful output or an error from a work result
//type WorkResultOutput struct {
//	Data  []byte        // Represents successful output (Y)
//	Error jam.EnumError // Represents error output (J)
//}

type WorkExecResult struct {
	inner any // Holds the value for the current variant (like a Rust enum variant)
}

func (wer *WorkExecResult) SetValue(value any) (err error) {
	switch v := value.(type) {
	case []byte:
		wer.inner = v
		return nil
	case jam.EnumError:
		wer.inner = v
		return nil
	default:
		return fmt.Errorf(jam.ErrUnsupportedType, v)
	}
}

func (wer WorkExecResult) IndexValue() (index uint, value any, err error) {
	switch wer.inner.(type) {
	case []byte:
		return 0, wer.inner, nil
	case jam.EnumError:
		return 1, wer.inner, nil
	}
	return 0, nil, jam.ErrUnsupportedEnumTypeValue
}

func (wer WorkExecResult) Value() (value any, err error) {
	_, value, err = wer.IndexValue()
	return
}

func (wer WorkExecResult) ValueAt(index uint) (value any, err error) {
	switch index {
	case 0:
		return []byte{}, nil
	case 1, 2, 3, 4:
		return jam.EnumError(index), nil
	}
	return nil, scale.ErrUnknownVaryingDataTypeValue
}

func (wer WorkExecResult) MarshalJSON() ([]byte, error) {
	value, err := wer.Value()
	if err != nil {
		return nil, err
	}

	switch v := value.(type) {
	case []byte:
		// Convert byte array to hex string
		hexValue := fmt.Sprintf("0x%x", v)
		return json.Marshal(map[string]interface{}{
			"ok": hexValue,
		})

	case jam.EnumError:
		var errName string
		switch v {
		case OutOfGas:
			errName = "out-of-gas"
		case UnexpectedTermination:
			errName = "panic"
		case CodeNotAvailable:
			errName = "bad-code"
		case CodeTooLarge:
			errName = "code-oversize"
		default:
			fmt.Println(v, value)
		}

		return json.Marshal(map[string]interface{}{
			errName: nil,
		})

	default:
		return nil, fmt.Errorf("unexpected type in WorkExecResult: %T", value)
	}
}

// IsSuccessful checks if the work result is successful
//func (wr WorkResult) IsSuccessful() bool {
//	return wr.Output.Error == NoError
//}

//// NewSuccessfulWorkResult creates a new successful WorkResult
//func NewSuccessfulWorkResult(serviceId ServiceId, serviceHashCode, payloadHash crypto.Hash, gasPrioritizationRatio uint64, output []byte) WorkResult {
//	return WorkResult{
//		ServiceId:              serviceId,
//		ServiceHashCode:        serviceHashCode,
//		PayloadHash:            payloadHash,
//		GasPrioritizationRatio: gasPrioritizationRatio,
//		Output:                 WorkResultOutput{Data: output, Error: NoError},
//	}
//}
//
//// NewErrorWorkResult creates a new error WorkResult
//func NewErrorWorkResult(serviceId ServiceId, serviceHashCode, payloadHash crypto.Hash, gasPrioritizationRatio uint64, errorResult WorkResultError) WorkResult {
//	return WorkResult{
//		ServiceId:              serviceId,
//		ServiceHashCode:        serviceHashCode,
//		PayloadHash:            payloadHash,
//		GasPrioritizationRatio: gasPrioritizationRatio,
//		Output:                 WorkResultOutput{Data: nil, Error: errorResult},
//	}
//}
