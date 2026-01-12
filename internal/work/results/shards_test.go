package results

import (
	"bytes"
	"testing"

	"github.com/eigerco/strawberry/internal/constants"
	"github.com/eigerco/strawberry/internal/erasurecoding"
	"github.com/eigerco/strawberry/internal/merkle/binary_tree"

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

func TestEraseBundleAndSegments(t *testing.T) {
	t.Run("auditable data and no segments", func(t *testing.T) {
		audBlob := []byte("auditable data")
		sd, err := ShardBundleAndSegments(audBlob, []work.Segment{})
		require.NoError(t, err)

		assert.Len(t, sd.Bundle, 1023)
		assert.Len(t, sd.Segments, 0)
		assert.Len(t, sd.BundleHashAndSegmentsRoot, 1023)
		for _, pair := range sd.BundleHashAndSegmentsRoot {
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
		sd, err := ShardBundleAndSegments(audBlob, []work.Segment{segment})
		require.NoError(t, err)

		assert.Len(t, sd.Bundle, 1023)
		assert.Equal(t, expectedSegmentsForShards, sd.Segments)
		assert.Len(t, sd.BundleHashAndSegmentsRoot, 1023)
		for i, pair := range sd.BundleHashAndSegmentsRoot {
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
		sd, err := ShardBundleAndSegments(audBlob, []work.Segment{segment1, segment2})
		require.NoError(t, err)

		assert.Len(t, sd.Bundle, 1023)
		assert.Equal(t, expectedSegmentsForShards, sd.Segments)
		assert.Len(t, sd.BundleHashAndSegmentsRoot, 1023)
		for i, pair := range sd.BundleHashAndSegmentsRoot {
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
			inputSegments: createSegments(constants.SegmentsPerPage),
			expectError:   false,
		},
		{
			name:          "multiple pages of segments",
			inputSegments: createSegments(constants.SegmentsPerPage * 2),
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
			expectedNumPages := len(tt.inputSegments) / constants.SegmentsPerPage
			assert.Equal(t, expectedNumPages, len(proofs))
		})
	}
}

func TestComputePagedProofsConsistency(t *testing.T) {
	// Create two identical sets of segments
	segments1 := createSegments(constants.SegmentsPerPage)
	segments2 := createSegments(constants.SegmentsPerPage)

	proofs1, err := ComputePagedProofs(segments1)
	require.NoError(t, err)

	proofs2, err := ComputePagedProofs(segments2)
	require.NoError(t, err)

	assert.Equal(t, len(proofs1), len(proofs2))
	for i := range proofs1 {
		assert.True(t, bytes.Equal(proofs1[i][:], proofs2[i][:]))
	}
}
