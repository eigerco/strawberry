package service_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/eigerco/strawberry/internal/common"
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/jamtime"
	"github.com/eigerco/strawberry/internal/service"
	"github.com/eigerco/strawberry/internal/state/serialization/statekey"
	"github.com/eigerco/strawberry/internal/testutils"
)

func TestServiceAccount_AddAndLookupPreimage(t *testing.T) {
	serviceAccount := service.ServiceAccount{
		Storage:                make(map[statekey.StateKey][]byte),
		PreimageLookup:         make(map[crypto.Hash][]byte),
		PreimageMeta:           make(map[service.PreImageMetaKey]service.PreimageHistoricalTimeslots),
		CodeHash:               testutils.RandomHash(t),
		Balance:                1000,
		GasLimitForAccumulator: common.MaxAllocatedGasAccumulation,
		GasLimitOnTransfer:     common.MaxAllocatedGasAccumulation,
	}

	preimage := []byte("example code")
	preimageHash := crypto.HashData(preimage)
	currentTimeslot := jamtime.CurrentTimeslot()

	// Preimage unavailable
	p := serviceAccount.LookupPreimage(currentTimeslot, preimageHash)
	require.Nil(t, p)

	err := serviceAccount.AddPreimage(preimage, currentTimeslot)
	require.NoError(t, err)
	p = serviceAccount.LookupPreimage(currentTimeslot, preimageHash)
	require.NotNil(t, p)
	require.Equal(t, preimage, p)
}

func TestServiceStateClone(t *testing.T) {
	storageKey := statekey.StateKey{0x1}
	preimageKey := crypto.Hash{0x2}
	preimageMetaKey := service.PreImageMetaKey{
		Hash:   preimageKey,
		Length: 8,
	}

	// Original with reference types
	original := service.ServiceState{
		0: service.ServiceAccount{
			Storage: map[statekey.StateKey][]byte{
				storageKey: []byte("storage"),
			},
			PreimageLookup: map[crypto.Hash][]byte{
				preimageKey: []byte("preimage"),
			},
			PreimageMeta: map[service.PreImageMetaKey]service.PreimageHistoricalTimeslots{
				preimageMetaKey: service.PreimageHistoricalTimeslots([]jamtime.Timeslot{1}),
			},
		},
		1: service.ServiceAccount{},
	}

	// Make deep copy
	cloned := original.Clone()

	// Modify the original's reference types
	original[0].Storage[storageKey][0] = 'x'
	original[0].PreimageLookup[preimageKey][0] = 'x'
	original[0].PreimageMeta[preimageMetaKey][0] = 2
	// Delete one of the service account entries
	delete(original, 0)

	// Verify the copy is unchanged
	require.Len(t, cloned, 2)
	require.Equal(t, []byte("storage"), cloned[0].Storage[storageKey])
	require.Equal(t, []byte("preimage"), cloned[0].PreimageLookup[preimageKey])
	require.Equal(t, service.PreimageHistoricalTimeslots([]jamtime.Timeslot{1}), cloned[0].PreimageMeta[preimageMetaKey])
	require.Nil(t, cloned[1].Storage)
	require.Nil(t, cloned[1].PreimageLookup)
	require.Nil(t, cloned[1].PreimageMeta)
}
