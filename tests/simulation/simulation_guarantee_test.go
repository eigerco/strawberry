//go:build integration

package simulation

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/state"
	"github.com/eigerco/strawberry/internal/statetransition"
	"github.com/eigerco/strawberry/internal/store"
	jsonutils "github.com/eigerco/strawberry/internal/testutils/json"
	"github.com/eigerco/strawberry/pkg/db/pebble"
)

// TestSimulateGuarantee simulates processing a block containing a guarantee and verifies that:
// - A block with a valid work report and 3 guarantor signatures is imported.
// - The core assignment includes the expected work report.
// - The used authorizer is removed from the core's authorization pool after processing.
func TestSimulateGuarantee(t *testing.T) {
	data, err := os.ReadFile("keys.json")
	require.NoError(t, err)

	// Genesis validator keys
	var keys []ValidatorKeys
	err = json.Unmarshal(data, &keys)
	require.NoError(t, err)

	// Genesis state
	data, err = os.ReadFile("guarantee_prestate_001.json")
	require.NoError(t, err)
	var currentState *state.State
	restoredState := jsonutils.RestoreStateSnapshot(data)
	currentState = &restoredState

	// guarantee block
	data, err = os.ReadFile("guarantee_block_001.json")
	require.NoError(t, err)
	testBlock := jsonutils.RestoreBlockSnapshot(data)

	// Trie DB for merklization
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

	report := testBlock.Extrinsic.EG.Guarantees[0].WorkReport
	coreIndex := report.CoreIndex

	require.Equal(t, report.AuthorizerHash, currentState.CoreAuthorizersPool[coreIndex][0])

	// Update state
	err = statetransition.UpdateState(
		currentState,
		testBlock,
		chainDB,
		trieDB,
	)
	require.NoError(t, err)

	require.Equal(t, testBlock.Header.TimeSlotIndex, currentState.TimeslotIndex)

	// Core assignment for the report's core should be set.
	require.NotNil(t, currentState.CoreAssignments[coreIndex])

	// And the assigned report should match the one in the guarantee.
	assignment := currentState.CoreAssignments[coreIndex]
	require.Equal(t, report, assignment.WorkReport)

	// Ensure the used authorizer has been removed from the pool.
	require.Equal(t, crypto.Hash{}, currentState.CoreAuthorizersPool[coreIndex][0])
}
