package work_test

import (
	"bytes"
	"github.com/eigerco/strawberry/internal/polkavm"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/eigerco/strawberry/internal/block"
	"github.com/eigerco/strawberry/internal/common"
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/jamtime"
	"github.com/eigerco/strawberry/internal/service"
	"github.com/eigerco/strawberry/internal/work"
)

// Helper functions
func createTestSegment(pattern byte) (seg polkavm.Segment) {
	for i := range seg {
		seg[i] = pattern
	}
	return seg
}

func createSegments(count int) []polkavm.Segment {
	segments := make([]polkavm.Segment, count)
	for i := range segments {
		segments[i] = createTestSegment(0x42)
	}
	return segments
}

func Test_ValidateNumberOfEntries(t *testing.T) {
	p := work.Package{
		WorkItems: []work.Item{
			{ExportedSegments: 100, ImportedSegments: make([]work.ImportedSegment, 500)},
			{ExportedSegments: 500, ImportedSegments: make([]work.ImportedSegment, 1000)},
		},
	}

	err := p.ValidateNumberOfEntries()
	assert.NoError(t, err)

	// Exceeding limits
	p.WorkItems[1].ExportedSegments = 2000
	err = p.ValidateNumberOfEntries()
	assert.Error(t, err)

	// Restore and break imported
	p.WorkItems[1].ExportedSegments = 500
	p.WorkItems[1].ImportedSegments = make([]work.ImportedSegment, 3000)
	err = p.ValidateNumberOfEntries()
	assert.Error(t, err)
}

func Test_ValidateSize(t *testing.T) {
	p := work.Package{
		AuthorizationToken: []byte("auth"),
		Parameterization:   []byte("param"),
		WorkItems: []work.Item{
			{
				Payload: []byte("payload"),
			},
		},
	}

	err := p.ValidateSize()
	assert.NoError(t, err)

	// over the limit
	hugePayload := make([]byte, work.MaxSizeOfEncodedWorkPackage+1)
	p.WorkItems[0].Payload = hugePayload

	err = p.ValidateSize()
	assert.Error(t, err)
}

func Test_ValidateGas(t *testing.T) {
	p := work.Package{
		WorkItems: []work.Item{
			{GasLimitRefine: 50, GasLimitAccumulate: 100},
			{GasLimitRefine: 100, GasLimitAccumulate: 500},
		},
	}

	err := p.ValidateGas()
	assert.NoError(t, err)

	// Exceed refine
	p.WorkItems[1].GasLimitRefine = work.MaxAllocatedGasRefine + 1
	err = p.ValidateGas()
	assert.Error(t, err)

	// Reset and exceed accumulate
	p.WorkItems[1].GasLimitRefine = 100
	p.WorkItems[1].GasLimitAccumulate = common.MaxAllocatedGasAccumulation + 1
	err = p.ValidateGas()
	assert.Error(t, err)
}

func Test_ComputeAuthorizerHashes(t *testing.T) {
	preimage := []byte("authorization_code")
	timeslot := jamtime.Timeslot(42)

	h := crypto.HashData(preimage)
	sa := service.ServiceAccount{
		Storage:        make(map[crypto.Hash][]byte),
		PreimageLookup: make(map[crypto.Hash][]byte),
		PreimageMeta:   make(map[service.PreImageMetaKey]service.PreimageHistoricalTimeslots),
	}

	sa.PreimageLookup[h] = preimage
	metaKey := service.PreImageMetaKey{Hash: h, Length: service.PreimageLength(len(preimage))}
	sa.PreimageMeta[metaKey] = service.PreimageHistoricalTimeslots{timeslot}

	serviceState := service.ServiceState{
		1: sa,
	}

	p := work.Package{
		AuthorizerService: 1,
		AuthCodeHash:      crypto.HashData(preimage),
		Parameterization:  []byte("param"),
		Context: block.RefinementContext{
			LookupAnchor: block.RefinementContextLookupAnchor{
				Timeslot: timeslot,
			},
		},
	}

	pc, pa, err := p.ComputeAuthorizerHashes(serviceState)
	require.NoError(t, err)

	assert.Equal(t, preimage, pc)

	expectedPa := crypto.HashData(append(pc, p.Parameterization...))
	assert.Equal(t, expectedPa, pa)

	// not found
	p.AuthCodeHash = crypto.HashData([]byte("nonexistent"))
	_, _, err = p.ComputeAuthorizerHashes(serviceState)
	assert.Error(t, err)
}

func TestComputePagedProofs(t *testing.T) {
	tests := []struct {
		name          string
		inputSegments []polkavm.Segment
		expectError   bool
		errorMessage  string
	}{
		{
			name:          "empty segments",
			inputSegments: []polkavm.Segment{},
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
			proofs, err := work.ComputePagedProofs(tt.inputSegments)

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

	proofs1, err := work.ComputePagedProofs(segments1)
	require.NoError(t, err)

	proofs2, err := work.ComputePagedProofs(segments2)
	require.NoError(t, err)

	assert.Equal(t, len(proofs1), len(proofs2))
	for i := range proofs1 {
		assert.True(t, bytes.Equal(proofs1[i][:], proofs2[i][:]))
	}
}
