package work_test

import (
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

func Test_ValidateNumberOfEntries(t *testing.T) {
	p := work.Package{
		WorkItems: []work.Item{
			{ExportedSegments: 100, ImportedSegments: make([]work.ImportedSegment, 500)},
			{ExportedSegments: 500, ImportedSegments: make([]work.ImportedSegment, 1000)},
		},
	}

	err := p.ValidateLimits()
	assert.NoError(t, err)

	// Exceeding limits
	p.WorkItems[1].ExportedSegments = 3000
	err = p.ValidateLimits()
	assert.Error(t, err)

	// Restore and break imported
	p.WorkItems[1].ExportedSegments = 500
	p.WorkItems[1].ImportedSegments = make([]work.ImportedSegment, 3000)
	err = p.ValidateLimits()
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
		Storage:        service.NewAccountStorage(),
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
