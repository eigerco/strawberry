package results

import (
	"bytes"
	"github.com/eigerco/strawberry/internal/erasurecoding"
	"github.com/eigerco/strawberry/internal/merkle/binary_tree"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/work"
)

// Helper functions
func createTestSegment(pattern byte) (seg work.Segment) {
	for i := range seg {
		seg[i] = pattern
	}
	return seg
}

func createSegments(count int) []work.Segment {
	segments := make([]work.Segment, count)
	for i := range segments {
		segments[i] = createTestSegment(0x42)
	}
	return segments
}

func TestBuildImportedSegments(t *testing.T) {
	segmentRootH := crypto.HashData([]byte("rootH"))

	mockSegmentData := map[crypto.Hash][]byte{
		segmentRootH: []byte("segment data #1"),
	}

	computation := NewComputation(mockAuthorizationInvoker{}, mockRefineInvoker{}, nil, mockSegmentData, nil)

	item := work.Item{
		ImportedSegments: []work.ImportedSegment{
			{Hash: segmentRootH},
		},
	}

	segments, _, err := computation.buildImportedSegments(item)
	require.NoError(t, err)
	require.Len(t, segments, 1)

	assert.Equal(t, "segment data #1", string(segments[0][:len("segment data #1")]))
}

func TestBuildExtrinsicData(t *testing.T) {
	exHash := crypto.HashData([]byte("extr1"))
	preimage := []byte("my extrinsic #1")

	mockExtrinsicPreimages := map[crypto.Hash][]byte{
		exHash: preimage,
	}

	computation := NewComputation(mockAuthorizationInvoker{}, mockRefineInvoker{}, nil, nil, mockExtrinsicPreimages)

	item := work.Item{
		Extrinsics: []work.Extrinsic{
			{
				Hash:   exHash,
				Length: uint32(len(preimage)),
			},
		},
	}

	xData, err := computation.buildExtrinsicData(item)
	require.NoError(t, err)
	require.Len(t, xData, 1)

	assert.Equal(t, preimage, xData[0])
}

func TestBuildAuditableWorkPackage(t *testing.T) {
	segRootH := crypto.HashData([]byte("rootH"))
	segData := []byte("segment data")
	exHash := crypto.HashData([]byte("extr1"))
	exData := []byte("extrinsic #1")

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
			},
		},
	}

	comp := NewComputation(mockAuthorizationInvoker{}, mockRefineInvoker{}, nil, segmentData, extrPre)

	audBlob, err := comp.buildAuditableWorkPackage(pkg)
	require.NoError(t, err)
	require.NotNil(t, audBlob)

	assert.Greater(t, len(audBlob), 0)
}

func TestComputeAvailabilitySpecifier(t *testing.T) {
	segData := []byte("segment data")
	audBlob := []byte("auditable data")

	exportedSegments := []work.Segment{
		{},
	}
	copy(exportedSegments[0][:], segData)

	packageHash := crypto.HashData([]byte("package"))

	comp := NewComputation(mockAuthorizationInvoker{}, mockRefineInvoker{}, nil, nil, nil)
	spec, err := comp.computeAvailabilitySpecifier(packageHash, audBlob, exportedSegments)
	require.NoError(t, err)
	require.NotNil(t, spec)

	assert.Equal(t, packageHash, spec.WorkPackageHash)
	assert.Equal(t, uint32(len(audBlob)), spec.AuditableWorkBundleLength)
	assert.NotEmpty(t, spec.SegmentRoot[:])
	assert.NotEmpty(t, spec.ErasureRoot[:])
}

func TestComputeShardData(t *testing.T) {
	t.Run("auditable data and no segments", func(t *testing.T) {
		audBlob := []byte("auditable data")
		auditableShards, shardsForSegments, auditableHashSegmentRootPairs, err := shardData(audBlob, []work.Segment{})
		require.NoError(t, err)

		assert.Len(t, auditableShards, 1023)
		assert.Len(t, shardsForSegments, 0)
		assert.Len(t, auditableHashSegmentRootPairs, 1023)
		for _, pair := range auditableHashSegmentRootPairs {
			assert.Len(t, pair, 32) // the pair should contain only one hash
		}
	})
	t.Run("auditable data and one segment", func(t *testing.T) {
		audBlob := []byte("auditable data")
		segment := work.Segment{}
		copy(segment[:], "segment data")
		segmentProofs, err := ComputePagedProofs([]work.Segment{segment})
		require.NoError(t, err)
		require.Len(t, segmentProofs, 1)

		segmentShards, err := erasurecoding.Encode(segment[:])
		require.NoError(t, err)

		segmentProofShards, err := erasurecoding.Encode(segmentProofs[0][:])
		require.NoError(t, err)

		expectedSegmentsForShards := make([][][]byte, 1023)
		for i := range expectedSegmentsForShards {
			assert.Len(t, segmentShards[i], 12)
			assert.Len(t, segmentProofShards[i], 12)

			require.NoError(t, err)
			expectedSegmentsForShards[i] = [][]byte{
				segmentShards[i],
				segmentProofShards[i],
			}

		}
		auditableShards, shardsForSegments, auditableHashSegmentRootPairs, err := shardData(audBlob, []work.Segment{segment})
		require.NoError(t, err)

		assert.Len(t, auditableShards, 1023)
		assert.Equal(t, expectedSegmentsForShards, shardsForSegments)
		assert.Len(t, auditableHashSegmentRootPairs, 1023)
		for i, pair := range auditableHashSegmentRootPairs {
			require.Len(t, pair, 64) // the pair should contain two hashes
			assert.Equal(t, crypto.Hash(pair[32:]), binary_tree.ComputeWellBalancedRoot([][]byte{segmentShards[i], segmentProofShards[i]}, crypto.HashData))
		}
	})
	t.Run("auditable data and two segments", func(t *testing.T) {
		audBlob := []byte("auditable data")
		segment1 := work.Segment{}
		copy(segment1[:], "segment data 1")

		segment2 := work.Segment{}
		copy(segment2[:], "segment data 2")

		segmentProofs, err := ComputePagedProofs([]work.Segment{segment1, segment2})
		require.NoError(t, err)
		require.Len(t, segmentProofs, 1)

		segment1Shards, err := erasurecoding.Encode(segment1[:])
		require.NoError(t, err)

		segment2Shards, err := erasurecoding.Encode(segment2[:])
		require.NoError(t, err)

		segmentProofShards, err := erasurecoding.Encode(segmentProofs[0][:])
		require.NoError(t, err)

		expectedSegmentsForShards := make([][][]byte, 1023)
		for i := range expectedSegmentsForShards {
			assert.Len(t, segment1Shards[i], 12)
			assert.Len(t, segment2Shards[i], 12)
			assert.Len(t, segmentProofShards[i], 12)

			require.NoError(t, err)
			expectedSegmentsForShards[i] = [][]byte{
				segment1Shards[i],
				segment2Shards[i],
				segmentProofShards[i],
			}
		}
		auditableShards, shardsForSegments, auditableHashSegmentRootPairs, err := shardData(audBlob, []work.Segment{segment1, segment2})
		require.NoError(t, err)

		assert.Len(t, auditableShards, 1023)
		assert.Equal(t, expectedSegmentsForShards, shardsForSegments)
		assert.Len(t, auditableHashSegmentRootPairs, 1023)
		for i, pair := range auditableHashSegmentRootPairs {
			_ = i
			require.Len(t, pair, 64) // the pair should contain two hashes
			assert.Equal(t, crypto.Hash(pair[32:]), binary_tree.ComputeWellBalancedRoot([][]byte{
				segment1Shards[i],
				segment2Shards[i],
				segmentProofShards[i],
			}, crypto.HashData))
		}
	})
}

func TestEvaluateWorkPackage(t *testing.T) {
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

	mockAuth := mockAuthorizationInvoker{}
	mockRefine := mockRefineInvoker{}
	comp := NewComputation(mockAuth, mockRefine, nil, segmentData, extrPre)

	report, err := comp.EvaluateWorkPackage(pkg, 1)
	require.NoError(t, err)
	require.NotNil(t, report)

	assert.NotEmpty(t, report.WorkPackageSpecification.WorkPackageHash)
	assert.Len(t, report.WorkResults, 1)
}

func TestComputePagedProofs(t *testing.T) {
	tests := []struct {
		name          string
		inputSegments []work.Segment
		expectError   bool
		errorMessage  string
	}{
		{
			name:          "empty segments",
			inputSegments: []work.Segment{},
			expectError:   false,
			errorMessage:  "no segments provided",
		},
		{
			name:          "single page of segments",
			inputSegments: createSegments(work.SegmentsPerPage),
			expectError:   false,
		},
		{
			name:          "multiple pages of segments",
			inputSegments: createSegments(work.SegmentsPerPage * 2),
			expectError:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			proofs, err := ComputePagedProofs(tt.inputSegments)

			if tt.expectError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMessage)
				return
			}

			require.NoError(t, err)
			expectedNumPages := len(tt.inputSegments) / work.SegmentsPerPage
			assert.Equal(t, expectedNumPages, len(proofs))
		})
	}
}

func TestComputePagedProofsConsistency(t *testing.T) {
	// Create two identical sets of segments
	segments1 := createSegments(work.SegmentsPerPage)
	segments2 := createSegments(work.SegmentsPerPage)

	proofs1, err := ComputePagedProofs(segments1)
	require.NoError(t, err)

	proofs2, err := ComputePagedProofs(segments2)
	require.NoError(t, err)

	assert.Equal(t, len(proofs1), len(proofs2))
	for i := range proofs1 {
		assert.True(t, bytes.Equal(proofs1[i][:], proofs2[i][:]))
	}
}

type mockAuthorizationInvoker struct{}

func (m mockAuthorizationInvoker) InvokePVM(workPackage work.Package, coreIndex uint16) ([]byte, error) {
	return []byte("Authorized"), nil
}

type mockRefineInvoker struct{}

func (m mockRefineInvoker) InvokePVM(
	itemIndex uint32,
	workPackage work.Package,
	authorizerHashOutput []byte,
	importedSegments []work.Segment,
	exportOffset uint64,
) ([]byte, []work.Segment, error) {
	out := []byte("RefineOutput")
	exported := []work.Segment{
		{},
	}
	return out, exported, nil
}
