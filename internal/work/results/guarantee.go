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
)

// GuaranteeManager handles the generation and validation of guarantees for work packages.
// Section 15 of the graypaper 0.6.1
type GuaranteeManager struct {
	computation *Computation
}

func NewGuaranteeManager(computation *Computation) *GuaranteeManager {
	if computation == nil {
		panic("computation cannot be nil")
	}
	return &GuaranteeManager{
		computation: computation,
	}
}

// ProcessWorkPackageGuarantee generates and validates a guarantee for a work package.
// This handles the local validator operations described in section 15 of the JAM graypaper.
// TODO: Missing (should be done in higher layers):
//   - Erasure Code chunks distribution across the validator set
//   - Cross-validator Consensus.
//   - Providing the work-package, extrinsic and exported data to other validators on request.
func (gp *GuaranteeManager) ProcessWorkPackageGuarantee(
	wp work.Package,
	coreIndex uint16,
	validatorIndex uint16,
	validatorPrivateKey ed25519.PrivateKey,
	validatorPublicKeys map[uint16]ed25519.PublicKey,
	authPool state.CoreAuthorizersPool, // Authorization pool from recent chain state
) (*block.Guarantee, error) {
	if validatorPrivateKey == nil {
		return nil, errors.New("validator key cannot be nil")
	}
	if validatorPublicKeys == nil {
		return nil, errors.New("public keys cannot be nil")
	}

	// Validate work package authorization
	if err := gp.validateWorkPackageAuthorization(wp, coreIndex, authPool); err != nil {
		return nil, fmt.Errorf("authorization validation failed: %w", err)
	}

	// Generate and validate work report.
	workReport, err := gp.computation.EvaluateWorkPackage(wp, coreIndex)
	if err != nil {
		return nil, fmt.Errorf("failed to generate work-report: %w", err)
	}

	// Validate work report output size
	if !workReport.OutputSizeIsValid() {
		return nil, errors.New("work report output size exceeds limit")
	}

	// Generate guarantee with validator signature
	guarantee, err := gp.GenerateGuarantee(workReport, validatorIndex, validatorPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to generate guarantee: %w", err)
	}

	// Validate the guarantee
	if err := ValidateGuarantee(guarantee, validatorPublicKeys); err != nil {
		return nil, fmt.Errorf("guarantee validation failed: %w", err)
	}

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
	validatorIndex uint16,
	validatorPrivateKey ed25519.PrivateKey,
) (*block.Guarantee, error) {
	if workReport == nil {
		return nil, errors.New("work report cannot be nil")
	}

	reportHash, err := workReport.Hash()
	if err != nil {
		return nil, fmt.Errorf("failed to compute work-report hash: %w", err)
	}

	signature := ed25519.Sign(validatorPrivateKey, reportHash[:])

	guarantee := &block.Guarantee{
		WorkReport: *workReport,
		Timeslot:   jamtime.CurrentTimeslot(),
		Credentials: []block.CredentialSignature{
			{
				ValidatorIndex: validatorIndex,
				Signature:      ([crypto.Ed25519SignatureSize]byte)(signature[:crypto.Ed25519SignatureSize]),
			},
		},
	}

	return guarantee, nil
}

// ValidateGuarantee checks if a guarantee is properly signed.
// Network-level validation (like duplicate checks) happens at a higher layer.
func ValidateGuarantee(guarantee *block.Guarantee, validatorPublicKeys map[uint16]ed25519.PublicKey) error {
	if guarantee == nil {
		return errors.New("guarantee cannot be nil")
	}

	if len(guarantee.Credentials) == 0 {
		return errors.New("guarantee has no credentials")
	}

	reportHash, err := guarantee.WorkReport.Hash()
	if err != nil {
		return fmt.Errorf("failed to compute report hash: %w", err)
	}

	for _, credential := range guarantee.Credentials {
		publicKey, exists := validatorPublicKeys[credential.ValidatorIndex]
		if !exists {
			return fmt.Errorf("validator %d public key not found", credential.ValidatorIndex)
		}

		if !ed25519.Verify(publicKey, reportHash[:], credential.Signature[:]) {
			return fmt.Errorf("invalid signature from validator %d", credential.ValidatorIndex)
		}
	}

	return nil
}
