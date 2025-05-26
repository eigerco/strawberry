package simulation

import (
	"os"
	"testing"

	"github.com/eigerco/strawberry/internal/block"
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/service"
	"github.com/eigerco/strawberry/internal/state"
	"github.com/eigerco/strawberry/internal/statetransition"
	"github.com/eigerco/strawberry/internal/store"
	jsonutils "github.com/eigerco/strawberry/internal/testutils/json"
	"github.com/eigerco/strawberry/pkg/db/pebble"
	"github.com/stretchr/testify/require"
)

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

	db, err := pebble.NewKVStore()
	require.NoError(t, err)
	defer func() {
		err := db.Close()
		require.NoError(t, err, "failed to close db")
	}()
	chainDB := store.NewChain(db)
	require.NoError(t, err)

	// Update state
	err = statetransition.UpdateState(
		currentState,
		testBlock,
		chainDB,
	)
	require.NoError(t, err)

	if len(testBlock.Extrinsic.EP) == 0 {
		t.Fatalf("block preimage missing")
	}

	serviceID := block.ServiceId(testBlock.Extrinsic.EP[0].ServiceIndex)
	preimageData := testBlock.Extrinsic.EP[0].Data
	preimageHash := crypto.HashData(preimageData)
	preimageMetaKey := service.PreImageMetaKey{
		Hash:   preimageHash,
		Length: service.PreimageLength(len(preimageData)),
	}

	if currentState.Services == nil {
		t.Fatalf("post state services map empty")
	}

	svc, ok := currentState.Services[serviceID]
	require.True(t, ok, "required service not found")

	require.Equal(t, svc.PreimageLookup[preimageHash], preimageData)
	require.Equal(t, svc.PreimageMeta[preimageMetaKey], service.PreimageHistoricalTimeslots{testBlock.Header.TimeSlotIndex})

	// TODO check activity stats once they are updated.
}
