//go:build integration

package simulation

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/eigerco/strawberry/internal/block"
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/service"
	"github.com/eigerco/strawberry/internal/state"
	"github.com/eigerco/strawberry/internal/state/serialization/statekey"
	"github.com/eigerco/strawberry/internal/statetransition"
	"github.com/eigerco/strawberry/internal/store"
	jsonutils "github.com/eigerco/strawberry/internal/testutils/json"
	"github.com/eigerco/strawberry/pkg/db/pebble"
)

// TestSimulatePreimage tests a very simple happy path for adding a preimage.
// We setup the state by ensuring that it has a service that is requesting that
// preimage, ie that it's lookup meta contains the preimages hash and length
// along with an empty historical timeslots array. We then submit a block with
// that same preimage, and ensure that it ends up being added the the service
// preimage lookup map, and also that it's preimage meta is updated to indicate
// that it's available since the header timeslot.
func TestSimulatePreimage(t *testing.T) {
	// Prestate
	data, err := os.ReadFile("preimage_prestate_001.json")
	require.NoError(t, err)
	var currentState *state.State
	restoredPreState := jsonutils.RestoreStateSnapshot(data)
	currentState = &restoredPreState

	// Block
	data, err = os.ReadFile("preimage_block_001.json")
	require.NoError(t, err)
	testBlock := jsonutils.RestoreBlockSnapshot(data)

	require.NotZero(t, len(testBlock.Extrinsic.EP), "block preimage missing")

	db, err := pebble.NewKVStore()
	require.NoError(t, err)
	defer func() {
		err := db.Close()
		require.NoError(t, err, "failed to close db")
	}()

	trieDB := store.NewTrie(db)
	require.NoError(t, err)

	chainDB := store.NewChain(db)
	require.NoError(t, err)

	// Update state
	err = statetransition.UpdateState(
		currentState,
		testBlock,
		chainDB,
		trieDB,
	)
	require.NoError(t, err)

	serviceID := block.ServiceId(testBlock.Extrinsic.EP[0].ServiceIndex)
	preimageData := testBlock.Extrinsic.EP[0].Data
	preimageHash := crypto.HashData(preimageData)

	if currentState.Services == nil {
		t.Fatalf("post state services map empty")
	}

	svc, ok := currentState.Services[serviceID]
	require.True(t, ok, "required service not found")

	// Preimage was correctly added to the service and it's lookup meta updated.
	require.Equal(t, svc.PreimageLookup[preimageHash], preimageData)

	k, err := statekey.NewPreimageMeta(serviceID, preimageHash, uint32(len(preimageData)))
	require.NoError(t, err)

	meta, ok := svc.GetPreimageMeta(k)
	require.True(t, ok)

	require.Equal(t, meta, service.PreimageHistoricalTimeslots{testBlock.Header.TimeSlotIndex})

	// TODO check activity stats once they are updated.
}
