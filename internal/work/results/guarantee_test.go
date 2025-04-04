package results

import (
	"crypto/ed25519"
	"github.com/eigerco/strawberry/internal/state"
	"github.com/eigerco/strawberry/internal/testutils"
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

func TestNewGuaranteeManager(t *testing.T) {
	t.Run("valid computation", func(t *testing.T) {
		computation := NewComputation(mockAuthorizationInvoker{}, mockRefineInvoker{}, nil, nil, nil)
		gm, err := NewGuaranteeManager(computation)
		require.NoError(t, err)
		assert.NotNil(t, gm)
		assert.Equal(t, computation, gm.computation)
	})

	t.Run("nil computation", func(t *testing.T) {
		gm, err := NewGuaranteeManager(nil)
		assert.Error(t, err)
		assert.Nil(t, gm)
		assert.Contains(t, err.Error(), "computation cannot be nil")
	})
}

func TestProcessWorkPackageGuarantee(t *testing.T) {
	// Generate test key pairs
	_, privateKey1, err := testutils.RandomED25519Keys(t)
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

	validPkg := work.Package{
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

	// Create a mock empty package for error cases
	emptyPkg := work.Package{}

	tests := []struct {
		name         string
		wp           work.Package
		coreIndex    uint16
		guarantorIdx uint16
		privKey      ed25519.PrivateKey
		authPool     state.CoreAuthorizersPool
		extraCreds   []block.CredentialSignature
		expectError  bool
		errorMessage string
	}{
		{
			name:         "successful guarantee generation",
			wp:           validPkg,
			coreIndex:    1,
			guarantorIdx: 1,
			privKey:      privateKey1,
			authPool:     EmptyCoreAuthorizersPool(),
			extraCreds: []block.CredentialSignature{
				{ValidatorIndex: 2, Signature: crypto.Ed25519Signature{1}}, // Add a second credential
			},
		},
		{
			name:         "empty package",
			wp:           emptyPkg,
			coreIndex:    1,
			guarantorIdx: 1,
			privKey:      privateKey1,
			authPool:     EmptyCoreAuthorizersPool(),
			expectError:  true,
			errorMessage: "failed to generate guarantee",
		},
		{
			name:         "unauthorized work package",
			wp:           validPkg,
			coreIndex:    1,
			guarantorIdx: 1,
			privKey:      privateKey1,
			authPool:     state.CoreAuthorizersPool{}, // Empty pool
			expectError:  true,
			errorMessage: "work package not authorized for this core",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockAuth := mockAuthorizationInvoker{}
			mockRefine := mockRefineInvoker{}

			computation := NewComputation(mockAuth, mockRefine, nil, segmentData, extrPre)
			gm, err := NewGuaranteeManager(computation)
			require.NoError(t, err)

			// If we have extra credentials, we need to simulate receiving them
			// This simulates the process of receiving credentials from other guarantors
			if len(tt.extraCreds) > 0 {
				// Generate the initial credential
				workReport, err := gm.computation.EvaluateWorkPackage(tt.wp, tt.coreIndex)
				require.NoError(t, err)

				payloadHash, err := gm.hashCoreIndexWithWorkReport(workReport, tt.coreIndex)
				require.NoError(t, err)

				// Generate credential with the first private key
				initialCred := gm.generateCredentialSignature(tt.privKey, tt.guarantorIdx, payloadHash)

				// Simulate receiving credentials from other guarantors
				credentials := mergeAndSortCredentials([]block.CredentialSignature{initialCred}, tt.extraCreds)

				// Store credentials for later verification
				guarantee, err := gm.GenerateGuarantee(workReport, credentials)
				require.NoError(t, err)
				require.NotNil(t, guarantee)

				// Verify the guarantee has the correct number of credentials
				assert.Equal(t, len(tt.extraCreds)+1, len(guarantee.Credentials))
				return
			}

			// Normal test flow for error cases
			guarantee, err := gm.ProcessWorkPackageGuarantee(
				tt.wp,
				tt.coreIndex,
				tt.guarantorIdx,
				tt.privKey,
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
		})
	}
}

func TestGenerateGuarantee(t *testing.T) {
	_, privateKey1, err := testutils.RandomED25519Keys(t)
	require.NoError(t, err)
	_, privateKey2, err := testutils.RandomED25519Keys(t)
	require.NoError(t, err)

	validWorkReport := &block.WorkReport{
		CoreIndex: 1,
	}

	mockAuth := mockAuthorizationInvoker{}
	mockRefine := mockRefineInvoker{}
	computation := NewComputation(mockAuth, mockRefine, nil, nil, nil)
	gm, err := NewGuaranteeManager(computation)
	require.NoError(t, err)

	// Generate initial credentials
	payloadHash, err := gm.hashCoreIndexWithWorkReport(validWorkReport, 1)
	require.NoError(t, err)

	cred1 := gm.generateCredentialSignature(privateKey1, 1, payloadHash)
	cred2 := gm.generateCredentialSignature(privateKey2, 2, payloadHash)

	tests := []struct {
		name        string
		workReport  *block.WorkReport
		credentials []block.CredentialSignature
		expectError bool
		errorMsg    string
	}{
		{
			name:        "valid guarantee with 2 credentials",
			workReport:  validWorkReport,
			credentials: []block.CredentialSignature{cred1, cred2},
		},
		{
			name:        "nil work report",
			workReport:  nil,
			credentials: []block.CredentialSignature{cred1, cred2},
			expectError: true,
			errorMsg:    "work report cannot be nil",
		},
		{
			name:        "insufficient credentials",
			workReport:  validWorkReport,
			credentials: []block.CredentialSignature{cred1},
			expectError: true,
			errorMsg:    "must have 2-3 valid signatures",
		},
		{
			name:        "too many credentials",
			workReport:  validWorkReport,
			credentials: []block.CredentialSignature{cred1, cred2, cred1, cred2},
			expectError: true,
			errorMsg:    "must have 2-3 valid signatures",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			guarantee, err := gm.GenerateGuarantee(tt.workReport, tt.credentials)

			if tt.expectError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
				assert.Nil(t, guarantee)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, guarantee)
			assert.Equal(t, tt.workReport, &guarantee.WorkReport)
			assert.Equal(t, tt.credentials, guarantee.Credentials)
		})
	}
}

func TestMergeAndSortCredentials(t *testing.T) {
	cred1 := block.CredentialSignature{ValidatorIndex: 1, Signature: crypto.Ed25519Signature{1}}
	cred2 := block.CredentialSignature{ValidatorIndex: 2, Signature: crypto.Ed25519Signature{2}}
	cred3 := block.CredentialSignature{ValidatorIndex: 3, Signature: crypto.Ed25519Signature{3}}
	cred2Updated := block.CredentialSignature{ValidatorIndex: 2, Signature: crypto.Ed25519Signature{4}}

	tests := []struct {
		name      string
		existing  []block.CredentialSignature
		received  []block.CredentialSignature
		expected  []block.CredentialSignature
		checkSort bool
	}{
		{
			name:      "merge without duplicates",
			existing:  []block.CredentialSignature{cred1, cred2},
			received:  []block.CredentialSignature{cred3},
			expected:  []block.CredentialSignature{cred1, cred2, cred3},
			checkSort: true,
		},
		{
			name:      "merge with duplicates",
			existing:  []block.CredentialSignature{cred1, cred2},
			received:  []block.CredentialSignature{cred2Updated, cred3},
			expected:  []block.CredentialSignature{cred1, cred2Updated, cred3},
			checkSort: true,
		},
		{
			name:      "empty existing",
			existing:  []block.CredentialSignature{},
			received:  []block.CredentialSignature{cred1, cred2},
			expected:  []block.CredentialSignature{cred1, cred2},
			checkSort: true,
		},
		{
			name:      "empty received",
			existing:  []block.CredentialSignature{cred1, cred2},
			received:  []block.CredentialSignature{},
			expected:  []block.CredentialSignature{cred1, cred2},
			checkSort: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := mergeAndSortCredentials(tt.existing, tt.received)

			assert.Equal(t, len(tt.expected), len(result))

			if tt.checkSort {
				// Verify sorting
				for i := 1; i < len(result); i++ {
					assert.True(t, result[i-1].ValidatorIndex < result[i].ValidatorIndex)
				}
			}

			// Verify content matches expected
			resultMap := make(map[uint16]crypto.Ed25519Signature)
			for _, cred := range result {
				resultMap[cred.ValidatorIndex] = cred.Signature
			}

			expectedMap := make(map[uint16]crypto.Ed25519Signature)
			for _, cred := range tt.expected {
				expectedMap[cred.ValidatorIndex] = cred.Signature
			}

			assert.Equal(t, expectedMap, resultMap)
		})
	}
}
