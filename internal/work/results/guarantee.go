package results

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"github.com/eigerco/strawberry/internal/block"
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/jamtime"
	"github.com/eigerco/strawberry/internal/state"
	"github.com/eigerco/strawberry/internal/work"
	"github.com/eigerco/strawberry/pkg/serialization/codec/jam"
	"sort"
)

// GuaranteeManager handles the generation and validation of guarantees for work packages.
// Section 15 of the graypaper 0.6.2.
type GuaranteeManager struct {
	computation *Computation
}

func NewGuaranteeManager(computation *Computation) (*GuaranteeManager, error) {
	if computation == nil {
		return nil, errors.New("computation cannot be nil")
	}
	return &GuaranteeManager{
		computation: computation,
	}, nil
}

// ProcessWorkPackageGuarantee generates and validates a guarantee for a work package.
// This handles the operations within the guarantor which generates guarantee based on received package and collaborating with other guarantors.
// Section 15 of v0.6.2.
// TODO: Missing:
//   - CE 133 (Submission of a work-package from a builder to a guarantor)
//   - CE 134 (Sharing Work-Packages with Other Guarantors)
//   - CE 135 (Distributing Guarantees to Validators)
//   - CE 136 (Responding to Work-Report Requests)
func (gp *GuaranteeManager) ProcessWorkPackageGuarantee(
	wp work.Package,
	coreIndex uint16,
	guarantorIndex uint16,
	guarantorPrivateKey ed25519.PrivateKey,
	authPool state.CoreAuthorizersPool,
) (*block.Guarantee, error) {
	// Validate work package authorization
	if err := gp.validateWorkPackageAuthorization(wp, coreIndex, authPool); err != nil {
		return nil, fmt.Errorf("authorization validation failed: %w", err)
	}

	// Generate work report. (15.01 v0.6.2)
	workReport, err := gp.computation.EvaluateWorkPackage(wp, coreIndex)
	if err != nil {
		return nil, fmt.Errorf("failed to generate work-report: %w", err)
	}

	// Validate work report output size
	if !workReport.OutputSizeIsValid() {
		return nil, errors.New("work report output size exceeds limit")
	}

	// Encode the work report and generate the payload hash (15.2 v0.6.2)
	payloadHash, err := gp.hashCoreIndexWithWorkReport(workReport, coreIndex)
	if err != nil {
		return nil, err
	}

	initialCredential := gp.generateCredentialSignature(guarantorPrivateKey, guarantorIndex, payloadHash)

	// TODO: CE 134 - Sharing Work-Packages with Other Guarantors to verify work report and receive guarantor credential signatures.
	var receivedCredentials []block.CredentialSignature // Here we would receive the credentials from other guarantors

	credentials := mergeAndSortCredentials([]block.CredentialSignature{initialCredential}, receivedCredentials)

	// Generate guarantee with guarantor signature
	guarantee, err := gp.GenerateGuarantee(workReport, credentials)
	if err != nil {
		return nil, fmt.Errorf("failed to generate guarantee: %w", err)
	}

	// TODO: CE 135 - Distribute Work-Report to Validators

	return guarantee, nil
}

// validateWorkPackageAuthorization checks if the work package is authorized
// according to the current authorization pool
func (gp *GuaranteeManager) validateWorkPackageAuthorization(
	wp work.Package,
	coreIndex uint16,
	authPool state.CoreAuthorizersPool,
) error {
	// Get authorizers for this core
	authorizers := authPool[coreIndex]

	authorized := false
	for _, authHash := range authorizers {
		if authHash == wp.AuthCodeHash {
			authorized = true
			break
		}
	}

	if !authorized {
		return errors.New("work package not authorized for this core")
	}

	return nil
}

// GenerateGuarantee creates a signed guarantee for a Work Report
func (gp *GuaranteeManager) GenerateGuarantee(
	workReport *block.WorkReport,
	credentials []block.CredentialSignature,
) (*block.Guarantee, error) {
	if workReport == nil {
		return nil, errors.New("work report cannot be nil")
	}

	// Validate we have 2-3 guarantor signatures
	if len(credentials) < 2 || len(credentials) > 3 {
		return nil, errors.New("must have 2-3 valid signatures")
	}

	// Construct the Guarantee struct (11.23 v0.6.2). EG ∈ [(w ∈ W, t ∈ NT, a ∈ [([NV, E])2,3)]C
	return &block.Guarantee{
		WorkReport:  *workReport,
		Timeslot:    jamtime.CurrentTimeslot(),
		Credentials: credentials,
	}, nil
}

// generateCredentialSignature creates a credential signature for a validator (implements part of 11.26 v0.6.2)
func (gp *GuaranteeManager) generateCredentialSignature(guarantorPrivateKey ed25519.PrivateKey, guarantorIndex uint16, reportPayloadHash crypto.Hash) block.CredentialSignature {
	message := append([]byte(state.SignatureContextGuarantee), reportPayloadHash[:]...)
	signature := ed25519.Sign(guarantorPrivateKey, message)
	credentials := block.CredentialSignature{
		ValidatorIndex: guarantorIndex,
		Signature:      crypto.Ed25519Signature(signature[:]),
	}

	return credentials
}

func (gp *GuaranteeManager) hashCoreIndexWithWorkReport(workReport *block.WorkReport, coreIndex uint16) (crypto.Hash, error) {
	// Encode each value
	encodedCoreIndex, err := jam.Marshal(coreIndex)
	if err != nil {
		return crypto.Hash{}, fmt.Errorf("failed to encode core index: %w", err)
	}

	encodedWorkReport, err := workReport.Encode()
	if err != nil {
		return crypto.Hash{}, fmt.Errorf("failed to encode work report hash: %w", err)
	}

	// Concatenate encoded values
	payload := append(encodedCoreIndex, encodedWorkReport...)

	payloadHash := crypto.HashData(payload)
	return payloadHash, nil
}

// Merge and sort credentials (11.25 v0.6.2). EG ∈ [(w ∈ W, t ∈ NT, a ∈ [([NV, E])2,3)]C
func mergeAndSortCredentials(existing, received []block.CredentialSignature) []block.CredentialSignature {
	// Use a map for deduplication
	credentialMap := make(map[uint16]block.CredentialSignature)

	for _, cred := range existing {
		credentialMap[cred.ValidatorIndex] = cred
	}

	for _, cred := range received {
		credentialMap[cred.ValidatorIndex] = cred // Overwrites duplicate indexes
	}

	// Convert map back to a slice
	mergedCredentials := make([]block.CredentialSignature, 0, len(credentialMap))
	for _, cred := range credentialMap {
		mergedCredentials = append(mergedCredentials, cred)
	}

	// Sort the credentials by ValidatorIndex
	sort.Slice(mergedCredentials, func(i, j int) bool {
		return mergedCredentials[i].ValidatorIndex < mergedCredentials[j].ValidatorIndex
	})

	return mergedCredentials
}
