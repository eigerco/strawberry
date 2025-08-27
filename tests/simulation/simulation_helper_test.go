//go:build integration && generate

package simulation

import (
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/eigerco/strawberry/internal/state"
	"github.com/eigerco/strawberry/internal/statetransition"
	"github.com/eigerco/strawberry/internal/store"
	jsonutils "github.com/eigerco/strawberry/internal/testutils/json"
	"github.com/eigerco/strawberry/pkg/db/pebble"
	"github.com/pmezard/go-difflib/difflib"
	"github.com/stretchr/testify/require"
)

// TestBlockGenerator is used to create valid blocks for simulation test
// purposes. It reads a prestate and block template and then produces a valid
// sealed block that it then applies to the prestate (using UpdateState). It
// then writes the resulting post state and block to files and prints the diff
// between the prestate and post state.
func TestBlockGenerator(t *testing.T) {
	preStateBytes, err := os.ReadFile("keys.json")
	require.NoError(t, err)

	// Genesis validator keys.
	var keys []ValidatorKeys
	err = json.Unmarshal(preStateBytes, &keys)
	require.NoError(t, err)

	// Prestate state. Change this to whatever your prestate is.
	preStateBytes, err = os.ReadFile("guarantee_prestate_001.json")
	require.NoError(t, err)
	var currentState *state.State
	restoredPreState := jsonutils.RestoreStateSnapshot(preStateBytes)
	currentState = &restoredPreState

	// Template block. Change this to your own block.
	blockBytes, err := os.ReadFile("guarantee_block_001.json")
	require.NoError(t, err)
	templateBlock := jsonutils.RestoreBlockSnapshot(blockBytes)

	// Trie DB for merklization.
	db, err := pebble.NewKVStore()
	require.NoError(t, err)
	defer func() {
		db.Close()
	}()

	trieDB := store.NewTrie(db)
	require.NoError(t, err)

	chainDB := store.NewChain(db)
	require.NoError(t, err)

	nextTimeslot := templateBlock.Header.TimeSlotIndex

	_, slotLeaderKey, err := FindSlotLeader(
		nextTimeslot,
		currentState,
		keys,
	)
	require.NoError(t, err)

	newBlock, err := ProduceBlock(
		nextTimeslot,
		templateBlock.Header.ParentHash,
		currentState,
		trieDB,
		slotLeaderKey,
		templateBlock.Extrinsic,
	)
	require.NoError(t, err)

	// Dump the valid sealed block
	err = os.MkdirAll("output", 0755)
	require.NoError(t, err)

	err = os.WriteFile("output/block_out.json", []byte(jsonutils.DumpBlockSnapshot(newBlock)), 0644)
	require.NoError(t, err)

	// Update state
	err = statetransition.UpdateState(
		currentState,
		newBlock,
		chainDB,
		trieDB,
	)
	require.NoError(t, err)

	// Dump the post state
	postStateDump := jsonutils.DumpStateSnapshot(*currentState)
	err = os.WriteFile("output/poststate_out.json", []byte(postStateDump), 0644)
	require.NoError(t, err)

	// Print diff
	diff, _ := difflib.GetUnifiedDiffString(difflib.UnifiedDiff{
		A:        difflib.SplitLines(string(preStateBytes)),
		B:        difflib.SplitLines(postStateDump),
		FromFile: "Expected",
		FromDate: "",
		ToFile:   "Actual",
		ToDate:   "",
		Context:  1,
	})
	fmt.Println(diff)
}
