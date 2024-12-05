package service_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/jamtime"
	"github.com/eigerco/strawberry/internal/service"
	"github.com/eigerco/strawberry/internal/testutils"
)

func TestServiceAccount_AddAndLookupPreimage(t *testing.T) {
	serviceAccount := service.ServiceAccount{
		Storage:                make(map[crypto.Hash][]byte),
		PreimageLookup:         make(map[crypto.Hash][]byte),
		PreimageMeta:           make(map[service.PreImageMetaKey]service.PreimageHistoricalTimeslots),
		CodeHash:               testutils.RandomHash(t),
		Balance:                1000,
		GasLimitForAccumulator: service.CoreGasAccumulation,
		GasLimitOnTransfer:     service.CoreGasAccumulation,
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
