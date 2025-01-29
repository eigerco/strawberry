package polkavm

import (
	"bytes"
	"testing"

	"github.com/eigerco/strawberry/internal/work"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Helper functions
func createTestSegment(pattern byte) (seg Segment) {
	for i := range seg {
		seg[i] = pattern
	}
	return seg
}

func createSegments(count int) []Segment {
	segments := make([]Segment, count)
	for i := range segments {
		segments[i] = createTestSegment(0x42)
	}
	return segments
}

func TestComputePagedProofs(t *testing.T) {
	tests := []struct {
		name          string
		inputSegments []Segment
		expectError   bool
		errorMessage  string
	}{
		{
			name:          "empty segments",
			inputSegments: []Segment{},
			expectError:   true,
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
			ctx := &RefineContextPair{
				IntegratedPVMMap: make(map[uint64]IntegratedPVM),
				Segments:         tt.inputSegments,
			}

			proofs, err := ComputePagedProofs(ctx)

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

	ctx1 := &RefineContextPair{
		IntegratedPVMMap: make(map[uint64]IntegratedPVM),
		Segments:         segments1,
	}

	ctx2 := &RefineContextPair{
		IntegratedPVMMap: make(map[uint64]IntegratedPVM),
		Segments:         segments2,
	}

	proofs1, err := ComputePagedProofs(ctx1)
	require.NoError(t, err)

	proofs2, err := ComputePagedProofs(ctx2)
	require.NoError(t, err)

	assert.Equal(t, len(proofs1), len(proofs2))
	for i := range proofs1 {
		assert.True(t, bytes.Equal(proofs1[i][:], proofs2[i][:]))
	}
}
