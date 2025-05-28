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

// TestSimulateAssurance simulates processing a block containing availability assurances and verifies that:
// - Core 0 receives >2/3 of validator assurances and is removed from core assignments as it becomes available.
// - Core 1 receives no assurances and remains in the core assignments after processing.
func TestSimulateAssurance(t *testing.T) {
	data, err := os.ReadFile("keys.json")
	require.NoError(t, err)

	// Genesis validator keys
	var keys []ValidatorKeys
	err = json.Unmarshal(data, &keys)
	require.NoError(t, err)

	// Genesis state
	data, err = os.ReadFile("assurance_prestate_001.json")
	require.NoError(t, err)
	var currentState *state.State
	restoredState := jsonutils.RestoreStateSnapshot(data)
	currentState = &restoredState

	// assurance block
	data, err = os.ReadFile("assurance_block_01.json")
	require.NoError(t, err)
	testBlock := jsonutils.RestoreBlockSnapshot(data)

	// Trie DB for merklization
	db, err := pebble.NewKVStore()
	require.NoError(t, err)
	defer func() {
		err := db.Close()
		require.NoError(t, err, "failed to close db")
	}()

	chainDB := store.NewChain(db)
	require.NoError(t, err)

	require.NotNil(t, currentState.CoreAssignments[0])
	require.NotNil(t, currentState.CoreAssignments[0].WorkReport)
	require.NotNil(t, currentState.CoreAssignments[1])
	require.NotNil(t, currentState.CoreAssignments[1].WorkReport)

	// Update state
	err = statetransition.UpdateState(
		currentState,
		testBlock,
		chainDB,
	)
	require.NoError(t, err)

	require.Equal(t, testBlock.Header.TimeSlotIndex, currentState.TimeslotIndex)

	// core 0 has become available and removed
	require.Nil(t, currentState.CoreAssignments[0])
	require.NotNil(t, currentState.CoreAssignments[1])
}
