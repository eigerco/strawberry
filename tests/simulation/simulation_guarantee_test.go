//go:build integration

package simulation

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/eigerco/strawberry/internal/state"
	"github.com/eigerco/strawberry/internal/statetransition"
	"github.com/eigerco/strawberry/internal/store"
	jsonutils "github.com/eigerco/strawberry/internal/testutils/json"
	"github.com/eigerco/strawberry/pkg/db/pebble"
)

func TestSimulateGuarantee(t *testing.T) {
	data, err := os.ReadFile("keys.json")
	require.NoError(t, err)

	// Genesis validator keys
	var keys []ValidatorKeys
	err = json.Unmarshal(data, &keys)
	require.NoError(t, err)

	// Genesis state
	data, err = os.ReadFile("genesis-state-tiny.json")
	require.NoError(t, err)
	var currentState *state.State
	restoredState := jsonutils.RestoreStateSnapshot(data)
	currentState = &restoredState

	// guarantee block
	data, err = os.ReadFile("guarantee_block_01.json")
	require.NoError(t, err)
	currentBlock := jsonutils.RestoreBlockSnapshot(data)

	// Trie DB for merklization
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
		currentBlock,
		chainDB,
	)

	require.NoError(t, err)
}
