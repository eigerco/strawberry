//go:build integration

package simulation

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/eigerco/strawberry/internal/state"
	"github.com/eigerco/strawberry/internal/statetransition"
	"github.com/eigerco/strawberry/internal/store"
	jsonutils "github.com/eigerco/strawberry/internal/testutils/json"
	"github.com/eigerco/strawberry/pkg/db/pebble"
	"github.com/stretchr/testify/require"
)

// TestSimulateDisputes tests:
// 1. adding a good report via a good verdict
// 2. adding a faulting validator via a fault on the good report
// 3. adding a culprit for a report in the bad report list
func TestSimulateDisputes(t *testing.T) {
	data, err := os.ReadFile("keys.json")
	require.NoError(t, err)

	// Genesis validator keys
	var keys []ValidatorKeys
	err = json.Unmarshal(data, &keys)
	require.NoError(t, err)
	// Prestate
	data, err = os.ReadFile("disputes_prestate_001.json")
	require.NoError(t, err)
	var currentState *state.State
	restoredPreState := jsonutils.RestoreStateSnapshot(data)
	currentState = &restoredPreState

	// Block
	data, err = os.ReadFile("disputes_block_001.json")
	require.NoError(t, err)
	testBlock := jsonutils.RestoreBlockSnapshot(data)

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

	require.Equal(t, testBlock.Extrinsic.ED.Verdicts[0].ReportHash, currentState.PastJudgements.GoodWorkReports[0])
	require.Equal(t, testBlock.Extrinsic.ED.Faults[0].ReportHash, currentState.PastJudgements.GoodWorkReports[0])
	require.Len(t, currentState.PastJudgements.OffendingValidators, 2, "Expected exactly two offenders")
	require.Contains(t, currentState.PastJudgements.OffendingValidators, testBlock.Extrinsic.ED.Culprits[0].ValidatorEd25519PublicKey)
	require.Contains(t, currentState.PastJudgements.OffendingValidators, testBlock.Extrinsic.ED.Faults[0].ValidatorEd25519PublicKey)

}
