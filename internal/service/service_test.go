package service_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/eigerco/strawberry/internal/block"
	"github.com/eigerco/strawberry/internal/common"
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/jamtime"
	"github.com/eigerco/strawberry/internal/service"
	"github.com/eigerco/strawberry/internal/state/serialization/statekey"
	"github.com/eigerco/strawberry/internal/testutils"
)

func TestServiceAccount_AddAndLookupPreimage(t *testing.T) {
	serviceAccount := service.ServiceAccount{
		PreimageLookup:         make(map[crypto.Hash][]byte),
		CodeHash:               testutils.RandomHash(t),
		Balance:                1000,
		GasLimitForAccumulator: common.MaxAllocatedGasAccumulation,
		GasLimitOnTransfer:     common.MaxAllocatedGasAccumulation,
	}

	preimage := []byte("example code")
	preimageHash := crypto.HashData(preimage)
	currentTimeslot := jamtime.CurrentTimeslot()

	serviceID := block.ServiceId(1)

	// Preimage unavailable
	p := serviceAccount.LookupPreimage(serviceID, currentTimeslot, preimageHash)
	require.Nil(t, p)

	err := serviceAccount.AddPreimage(serviceID, preimage, currentTimeslot)
	require.NoError(t, err)
	p = serviceAccount.LookupPreimage(serviceID, currentTimeslot, preimageHash)
	require.NotNil(t, p)
	require.Equal(t, preimage, p)
}

func TestServiceStateClone(t *testing.T) {
	storageKey := statekey.StateKey{0x1}
	preimageKey := crypto.Hash{0x2}

	sa := service.ServiceAccount{
		PreimageLookup: map[crypto.Hash][]byte{
			preimageKey: []byte("preimage"),
		},
	}

	sa.InsertStorage(storageKey, 1, []byte("storage"))

	// Original with reference types
	original := service.ServiceState{
		0: sa,
		1: service.ServiceAccount{},
	}

	// Make deep copy
	cloned := original.Clone()

	// Modify the original's reference types
	original0 := original[0]
	val, ok := original0.GetStorage(storageKey)
	require.True(t, ok)
	val[0] = 'x'
	original[0].PreimageLookup[preimageKey][0] = 'x'
	// Delete one of the service account entries
	delete(original, 0)

	// Verify the copy is unchanged
	require.Len(t, cloned, 2)
	account0 := cloned[0]
	val, ok = account0.GetStorage(storageKey)
	require.True(t, ok)
	require.Equal(t, []byte("storage"), val)
	require.Equal(t, []byte("preimage"), cloned[0].PreimageLookup[preimageKey])
	require.Nil(t, cloned[1].PreimageLookup)
}
