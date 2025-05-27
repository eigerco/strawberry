//go:build integration

package simulation

import (
	"os"
	"testing"

	"github.com/eigerco/strawberry/internal/state"
	"github.com/eigerco/strawberry/internal/statetransition"
	"github.com/eigerco/strawberry/internal/store"
	jsonutils "github.com/eigerco/strawberry/internal/testutils/json"
	"github.com/eigerco/strawberry/pkg/db/pebble"
	"github.com/stretchr/testify/require"
)

// TestSimulateDisputes tests a very simple happy path for adding a dispute. We
// create a dispute with 2/3 of the validators voting that the report was good.
// This naturally implies that there is at least one validator at fault. We add
// two validators at fault who incorrectly said that the report was bad. We
// expect the report to be added the 'good' set of reports in the judgements
// state. We also expect that each of the offenders are added to the offenders
// list in order.
func TestSimulateDisputes(t *testing.T) {
	// Prestate
	data, err := os.ReadFile("disputes_prestate_001.json")
	require.NoError(t, err)
	var currentState *state.State
	restoredPreState := jsonutils.RestoreStateSnapshot(data)
	currentState = &restoredPreState

	// Block
	data, err = os.ReadFile("disputes_block_001.json")
	require.NoError(t, err)
	testBlock := jsonutils.RestoreBlockSnapshot(data)

	if len(testBlock.Extrinsic.ED.Verdicts) == 0 {
		t.Fatalf("block disputes missing")
	}

	if len(testBlock.Extrinsic.ED.Faults) < 2 {
		t.Fatalf("missing faluts")
	}

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

	// Check that verdict report is put into the 'good' set.
	require.Equal(t, testBlock.Extrinsic.ED.Verdicts[0].ReportHash, currentState.PastJudgements.GoodWorkReports[0])

	// Check the faults, we expect each fault to point to the same good work
	// report hash, and also that each faulty validator is added to the state's
	// offenders list.
	require.Equal(t, testBlock.Extrinsic.ED.Faults[0].ReportHash, currentState.PastJudgements.GoodWorkReports[0])
	require.Equal(t, testBlock.Extrinsic.ED.Faults[0].ValidatorEd25519PublicKey, currentState.PastJudgements.OffendingValidators[0])
	require.Equal(t, testBlock.Extrinsic.ED.Faults[1].ReportHash, currentState.PastJudgements.GoodWorkReports[0])
	require.Equal(t, testBlock.Extrinsic.ED.Faults[1].ValidatorEd25519PublicKey, currentState.PastJudgements.OffendingValidators[1])
}
