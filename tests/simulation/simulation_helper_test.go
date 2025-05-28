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

// TestGenerateGenesisState is used to create valid blocks for simulation test
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
	preStateBytes, err = os.ReadFile("genesis-state-tiny.json")
	require.NoError(t, err)
	var currentState *state.State
	restoredPreState := jsonutils.RestoreStateSnapshot(preStateBytes)
	currentState = &restoredPreState

	// Template block. Change this to your own block.
	blockBytes, err := os.ReadFile("sample_block.json")
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

	// Dump the valid selaed block
	os.WriteFile("block_out.json", []byte(jsonutils.DumpBlockSnapshot(newBlock)), 0644)

	// Update state
	err = statetransition.UpdateState(
		currentState,
		newBlock,
		chainDB,
	)
	require.NoError(t, err)

	// Dump the post state
	postStateDump := jsonutils.DumpStateSnapshot(*currentState)
	os.WriteFile("poststate_out.json", []byte(postStateDump), 0644)

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
