package results

import (
	"crypto/ed25519"
	"github.com/eigerco/strawberry/internal/state"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/eigerco/strawberry/internal/block"
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/work"
)

func EmptyCoreAuthorizersPool() state.CoreAuthorizersPool {
	var pool state.CoreAuthorizersPool
	for i := range pool {
		for range state.MaxAuthorizersPerCore {
			pool[i] = append(pool[i], crypto.Hash{})
		}
	}
	return pool
}

func TestProcessWorkPackageGuarantee(t *testing.T) {
	// Generate test key pair
	pubKey, privKey, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	segRootH := crypto.HashData([]byte("rootH"))
	segData := []byte("some segment data")

	exData := []byte("extrinsic #1")
	exHash := crypto.HashData(exData)

	segmentData := map[crypto.Hash][]byte{
		segRootH: segData,
	}
	extrPre := map[crypto.Hash][]byte{
		exHash: exData,
	}

	pkg := work.Package{
		WorkItems: []work.Item{
			{
				ImportedSegments: []work.ImportedSegment{
					{Hash: segRootH},
				},
				Extrinsics: []work.Extrinsic{
					{
						Hash:   exHash,
						Length: uint32(len(exData)),
					},
				},
				ExportedSegments: 1,
			},
		},
	}

	tests := []struct {
		name                string
		wp                  work.Package
		coreIndex           uint16
		validatorIdx        uint16
		validatorPrivateKey ed25519.PrivateKey
		validatorPublicKeys map[uint16]ed25519.PublicKey
		authPool            state.CoreAuthorizersPool
		expectError         bool
		errorMessage        string
	}{
		{
			name:                "successful guarantee generation",
			wp:                  pkg,
			coreIndex:           1,
			validatorIdx:        1,
			validatorPrivateKey: privKey,
			validatorPublicKeys: map[uint16]ed25519.PublicKey{1: pubKey},
			authPool:            EmptyCoreAuthorizersPool(),
		},
		{
			name:                "nil validator key",
			wp:                  work.Package{},
			coreIndex:           1,
			validatorIdx:        1,
			validatorPrivateKey: nil,
			validatorPublicKeys: map[uint16]ed25519.PublicKey{1: pubKey},
			authPool:            EmptyCoreAuthorizersPool(),
			expectError:         true,
			errorMessage:        "validator key cannot be nil",
		},
		{
			name:                "nil public keys",
			wp:                  work.Package{},
			coreIndex:           1,
			validatorIdx:        1,
			validatorPrivateKey: privKey,
			validatorPublicKeys: nil,
			authPool:            EmptyCoreAuthorizersPool(),
			expectError:         true,
			errorMessage:        "public keys cannot be nil",
		},
		{
			name:                "validator not in public keys",
			wp:                  pkg,
			coreIndex:           1,
			validatorIdx:        2, // Different from public keys
			validatorPrivateKey: privKey,
			validatorPublicKeys: map[uint16]ed25519.PublicKey{1: pubKey},
			authPool:            EmptyCoreAuthorizersPool(),
			expectError:         true,
			errorMessage:        "validator 2 public key not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockAuth := mockAuthorizationInvoker{}
			mockRefine := mockRefineInvoker{}

			computation := NewComputation(mockAuth, mockRefine, nil, segmentData, extrPre)
			gm := NewGuaranteeManager(computation)

			guarantee, err := gm.ProcessWorkPackageGuarantee(
				tt.wp,
				tt.coreIndex,
				tt.validatorIdx,
				tt.validatorPrivateKey,
				tt.validatorPublicKeys,
				tt.authPool,
			)

			if tt.expectError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMessage)
				assert.Nil(t, guarantee)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, guarantee)
			assert.Equal(t, tt.validatorIdx, guarantee.Credentials[0].ValidatorIndex)
			assert.NotEmpty(t, guarantee.Credentials[0].Signature)
		})
	}
}

func TestValidateGuarantee(t *testing.T) {
	pubKey, privKey, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	// Create a valid work report and guarantee for testing
	validWorkReport := &block.WorkReport{
		CoreIndex: 1,
	}
	reportHash, err := validWorkReport.Hash()
	require.NoError(t, err)

	signature := ed25519.Sign(privKey, reportHash[:])
	validGuarantee := &block.Guarantee{
		WorkReport: *validWorkReport,
		Credentials: []block.CredentialSignature{
			{
				ValidatorIndex: 1,
				Signature:      crypto.Ed25519Signature(signature[:]),
			},
		},
	}

	tests := []struct {
		name                string
		guarantee           *block.Guarantee
		validatorPublicKeys map[uint16]ed25519.PublicKey
		expectError         bool
		errorMessage        string
	}{
		{
			name:                "valid guarantee",
			guarantee:           validGuarantee,
			validatorPublicKeys: map[uint16]ed25519.PublicKey{1: pubKey},
		},
		{
			name:                "nil guarantee",
			guarantee:           nil,
			validatorPublicKeys: map[uint16]ed25519.PublicKey{1: pubKey},
			expectError:         true,
			errorMessage:        "guarantee cannot be nil",
		},
		{
			name: "no credentials",
			guarantee: &block.Guarantee{
				WorkReport:  *validWorkReport,
				Credentials: []block.CredentialSignature{},
			},
			validatorPublicKeys: map[uint16]ed25519.PublicKey{1: pubKey},
			expectError:         true,
			errorMessage:        "guarantee has no credentials",
		},
		{
			name:                "validator not in public keys",
			guarantee:           validGuarantee,
			validatorPublicKeys: map[uint16]ed25519.PublicKey{2: pubKey}, // Different validator index
			expectError:         true,
			errorMessage:        "validator 1 public key not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateGuarantee(tt.guarantee, tt.validatorPublicKeys)

			if tt.expectError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMessage)
				return
			}

			require.NoError(t, err)
		})
	}
}

func TestNewGuaranteeManager(t *testing.T) {
	t.Run("valid computation", func(t *testing.T) {
		computation := NewComputation(mockAuthorizationInvoker{}, mockRefineInvoker{}, nil, nil, nil)
		gm := NewGuaranteeManager(computation)
		assert.NotNil(t, gm)
		assert.Equal(t, computation, gm.computation)
	})

	t.Run("nil computation", func(t *testing.T) {
		assert.Panics(t, func() {
			NewGuaranteeManager(nil)
		})
	})
}
