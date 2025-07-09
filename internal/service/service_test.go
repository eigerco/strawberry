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

func TestThresholdBalanceStorage(t *testing.T) {
	sa := service.NewServiceAccount()
	serviceID := block.ServiceId(1)

	originalKey := []byte("fooKey")
	key, err := statekey.NewStorage(serviceID, originalKey)
	require.NoError(t, err)

	value := []byte("barValue")

	sa.InsertStorage(key, uint64(len(originalKey)), value)

	ai := uint64(1)
	ao := uint64(34 + len(originalKey) + len(value))
	expected := service.BasicMinimumBalance +
		service.AdditionalMinimumBalancePerItem*ai +
		service.AdditionalMinimumBalancePerOctet*ao

	require.Equal(t, expected, sa.ThresholdBalance())

	// re‐insert - assert that neither ai nor ao changes the second time
	sa.InsertStorage(key, uint64(len(originalKey)), []byte("fooValue"))
	require.Equal(t, expected, sa.ThresholdBalance())

	// delete
	sa.DeleteStorage(key, uint64(len(originalKey)), uint64(len(value)))
	require.Equal(t, uint64(service.BasicMinimumBalance), sa.ThresholdBalance())
}

func TestThresholdBalancePreimage(t *testing.T) {
	sa := service.NewServiceAccount()
	serviceID := block.ServiceId(1)

	preimage := []byte("preimage")

	h := crypto.HashData(preimage)
	k, err := statekey.NewPreimageMeta(serviceID, h, uint32(len(preimage)))
	require.NoError(t, err)

	err = sa.InsertPreimageMeta(k, uint64(len(preimage)), service.PreimageHistoricalTimeslots{})
	require.NoError(t, err)

	ai := uint64(2)
	ao := uint64(81 + len(preimage))
	expected := service.BasicMinimumBalance +
		service.AdditionalMinimumBalancePerItem*ai +
		service.AdditionalMinimumBalancePerOctet*ao

	require.Equal(t, expected, sa.ThresholdBalance())

	// update
	err = sa.UpdatePreimageMeta(k, service.PreimageHistoricalTimeslots{jamtime.Timeslot(100)})
	require.NoError(t, err)
	// threshold balance remains unchanged
	require.Equal(t, expected, sa.ThresholdBalance())

	// delete
	sa.DeletePreimageMeta(k, uint64(len(preimage)))
	require.Equal(t, uint64(service.BasicMinimumBalance), sa.ThresholdBalance())
}

func TestThresholdBalanceCombinedInserts(t *testing.T) {
	sa := service.NewServiceAccount()
	serviceID := block.ServiceId(1)

	originalKey := []byte("k")

	key, err := statekey.NewStorage(serviceID, originalKey)
	require.NoError(t, err)
	value := []byte("v")
	sa.InsertStorage(key, uint64(len(originalKey)), value)

	preimage := []byte("preimage")
	h := crypto.HashData(preimage)
	k, err := statekey.NewPreimageMeta(serviceID, h, uint32(len(preimage)))
	require.NoError(t, err)

	err = sa.InsertPreimageMeta(k, uint64(len(preimage)), service.PreimageHistoricalTimeslots{})
	require.NoError(t, err)

	sa.GratisStorageOffset = 20

	// ai = 1 (storage) + 2 (preimage) = 3
	// ao = (34+1+1) + (81+8) = 34+1+1 + 89 = 125
	// expected = 100 (BS) + 10 (BI) * 3 (ai) + 1 (BL) * 125 (ao) - 20 (gratis) = 235
	expected := service.BasicMinimumBalance +
		service.AdditionalMinimumBalancePerItem*(1+2) +
		service.AdditionalMinimumBalancePerOctet*(uint64(34+1+1)+uint64(81+len(preimage))) -
		sa.GratisStorageOffset

	require.Equal(t, expected, sa.ThresholdBalance())

	// test with a large gratis storage
	sa.GratisStorageOffset = 100000000
	require.Equal(t, uint64(0), sa.ThresholdBalance())
}
