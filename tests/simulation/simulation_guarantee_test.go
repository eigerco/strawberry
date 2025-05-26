//go:build integration

// Genesis state, block and keys adapted from: https://github.com/jam-duna/jamtestnet
package simulation

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/eigerco/strawberry/internal/block"
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/state"
	"github.com/eigerco/strawberry/internal/statetransition"
	"github.com/eigerco/strawberry/internal/store"
	"github.com/eigerco/strawberry/internal/testutils"
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
	currentBlock := jsonutils.RestoreBlock(data)

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

	currentTimeslot := currentBlock.Header.TimeSlotIndex
	slotLeaderKey := crypto.BandersnatchPrivateKey{}
	slotLeaderName := ""

	// Find the slot leader
	found := false
	for _, k := range keys {
		key := crypto.BandersnatchPrivateKey(testutils.MustFromHex(t, k.BandersnatchPrivate))
		ok, err := isSlotLeader(currentTimeslot, currentState, key)
		require.NoError(t, err)
		if ok {
			slotLeaderKey = key
			slotLeaderName = k.Name
			found = true
			break
		}
	}
	require.True(t, found, "slot leader not found")

	require.NotEqual(t, slotLeaderKey, crypto.BandersnatchPrivateKey{})
	t.Logf("slot leader: %s", slotLeaderName)

	headerHash, err := currentBlock.Header.Hash()
	require.NoError(t, err)

	ticketAttempts := map[string]int{}
	for _, k := range keys {
		ticketAttempts[k.Name] = 0
	}

	// Submit tickets if possible
	ticketProofs := submitTickets(t, keys, currentState, currentTimeslot, ticketAttempts)

	newBlock, err := produceBlock(
		currentTimeslot,
		headerHash,
		currentState,
		trieDB,
		slotLeaderKey,
		ticketProofs,
		block.Extrinsic{
			EG: currentBlock.Extrinsic.EG,
		},
	)
	require.NoError(t, err)

	t.Logf("block prior state root: %v", hex.EncodeToString(newBlock.Header.PriorStateRoot[:]))
	t.Logf("block parent hash: %v", hex.EncodeToString(newBlock.Header.ParentHash[:]))

	// Update state
	err = statetransition.UpdateState(
		currentState,
		newBlock,
		chainDB,
	)

	require.NoError(t, err)
}
