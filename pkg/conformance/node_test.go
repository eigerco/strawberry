//go:build tiny

package conformance

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/eigerco/strawberry/internal/block"
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/jamtime"
	"github.com/eigerco/strawberry/internal/merkle/trie"
	"github.com/eigerco/strawberry/internal/state/serialization"
	"github.com/eigerco/strawberry/internal/state/serialization/statekey"
	"github.com/eigerco/strawberry/internal/statetransition"
	"github.com/eigerco/strawberry/internal/store"
	jsonutils "github.com/eigerco/strawberry/internal/testutils/json"
	"github.com/eigerco/strawberry/pkg/db/pebble"
	"github.com/eigerco/strawberry/pkg/network/handlers"
	"github.com/eigerco/strawberry/pkg/serialization/codec/jam"
	"github.com/eigerco/strawberry/tests/simulation"
)

func TestMessage(t *testing.T) {
	socketPath := "/tmp/test_socket"

	db, err := pebble.NewKVStore()
	assert.NoError(t, err)
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Log("db close error:", err)
		}
	})

	chain := store.NewChain(db)
	trieStore := store.NewTrie(chain)

	appName := []byte("app name")
	appVersion := Version{1, 2, 3}
	jamVersion := Version{4, 5, 6}
	features := FeatureFork

	go func() {
		n := NewNode(socketPath, chain, trieStore, appName, appVersion, jamVersion, features)
		if err := n.Start(); err != nil {
			t.Logf("failed to start Node: %v", err)
		}
		t.Cleanup(func() {
			if err := n.Stop(); err != nil {
				t.Logf("failed to stop Node: %v", err)
			}
		})
	}()

	time.Sleep(1 * time.Second)

	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		panic(err)
	}
	t.Cleanup(func() {
		if err := conn.Close(); err != nil {
			t.Logf("failed to close connection: %v", err)
		}
	})

	// exchange peer info and handshake
	requestMsg := NewMessage(PeerInfo{
		Name:       []byte("app name"),
		AppVersion: Version{7, 8, 9},
		JamVersion: Version{10, 11, 12},
	})

	msgBytes, err := jam.Marshal(requestMsg)
	assert.NoError(t, err)

	ctx := context.Background()

	err = handlers.WriteMessageWithContext(ctx, conn, msgBytes)
	assert.NoError(t, err)

	bb, err := handlers.ReadMessageWithContext(ctx, conn)
	assert.NoError(t, err)

	respMsg := &Message{}
	err = jam.Unmarshal(bb.Content, respMsg)
	require.NoError(t, err)

	assert.Equal(t, NewMessage(PeerInfo{
		Name:       appName,
		AppVersion: appVersion,
		JamVersion: jamVersion,
	}), respMsg)

	// set initial state
	data, err := os.ReadFile("../../tests/simulation/ticket_prestate_001.json")
	require.NoError(t, err)
	currentState := jsonutils.RestoreStateSnapshot(data)
	serializedState, err := serialization.SerializeState(currentState)
	require.NoError(t, err)

	currentStateItems := State{}
	for k, v := range serializedState {
		currentStateItems.StateItems = append(currentStateItems.StateItems, statekey.KeyValue{
			Key:   k,
			Value: v,
		})
	}

	currentTimeslot := jamtime.Timeslot(24)

	// Genesis validator keys.
	data, err = os.ReadFile("../../tests/simulation/keys.json")
	require.NoError(t, err)
	var keys []simulation.ValidatorKeys
	err = json.Unmarshal(data, &keys)
	require.NoError(t, err)

	// Find the slot leader.
	_, slotLeaderKey, err := simulation.FindSlotLeader(
		currentTimeslot,
		&currentState,
		keys,
	)
	require.NoError(t, err)

	genesisBlock, err := simulation.ProduceBlock(currentTimeslot, crypto.Hash{}, &currentState, trieStore, slotLeaderKey, block.Extrinsic{})
	require.NoError(t, err)

	requestMsg = NewMessage(Initialize{
		Header: genesisBlock.Header,
		State:  currentStateItems,
	})

	msgBytes, err = jam.Marshal(requestMsg)
	assert.NoError(t, err)

	err = handlers.WriteMessageWithContext(ctx, conn, msgBytes)
	assert.NoError(t, err)

	bb, err = handlers.ReadMessageWithContext(ctx, conn)
	assert.NoError(t, err)

	respMsg = &Message{}
	err = jam.Unmarshal(bb.Content, respMsg)
	require.NoError(t, err)

	assert.Equal(t, NewMessage(StateRoot{
		StateRootHash: computeStateRoot(t, serializedState),
	},
	), respMsg)

	block1, err := genesisBlock.Header.Hash()
	require.NoError(t, err)

	// import block

	currentTimeslot = currentTimeslot + 1
	// Find the slot leader for block 2
	_, slotLeaderKey, err = simulation.FindSlotLeader(
		currentTimeslot,
		&currentState,
		keys,
	)
	require.NoError(t, err)
	block2, err := simulation.ProduceBlock(currentTimeslot, block1, &currentState, trieStore, slotLeaderKey, block.Extrinsic{})
	require.NoError(t, err)

	requestMsg = NewMessage(ImportBlock{
		Block: block2,
	})

	msgBytes, err = jam.Marshal(requestMsg)
	assert.NoError(t, err)

	ctx = context.Background()

	err = handlers.WriteMessageWithContext(ctx, conn, msgBytes)
	assert.NoError(t, err)

	bb, err = handlers.ReadMessageWithContext(ctx, conn)
	assert.NoError(t, err)

	respMsg = &Message{}
	err = jam.Unmarshal(bb.Content, &respMsg)
	require.NoError(t, err)

	err = statetransition.UpdateState(&currentState, block2, chain, trieStore)
	assert.NoError(t, err)

	serializedState, err = serialization.SerializeState(currentState)
	require.NoError(t, err)

	assert.Equal(t, NewMessage(StateRoot{
		StateRootHash: computeStateRoot(t, serializedState),
	},
	), respMsg)

	// get state
	block2Hash, err := block2.Header.Hash()
	require.NoError(t, err)

	requestMsg = NewMessage(GetState{
		HeaderHash: block2Hash,
	})

	msgBytes, err = jam.Marshal(requestMsg)
	assert.NoError(t, err)

	ctx = context.Background()

	err = handlers.WriteMessageWithContext(ctx, conn, msgBytes)
	assert.NoError(t, err)

	bb, err = handlers.ReadMessageWithContext(ctx, conn)
	assert.NoError(t, err)

	respMsg = &Message{}
	err = jam.Unmarshal(bb.Content, &respMsg)
	require.NoError(t, err)

	expectedState := State{}
	for k, v := range serializedState {
		expectedState.StateItems = append(expectedState.StateItems, statekey.KeyValue{
			Key:   k,
			Value: v,
		})
	}
	slices.SortFunc(expectedState.StateItems, func(a, b statekey.KeyValue) int {
		if string(a.Key[:]) > string(b.Key[:]) {
			return 1
		} else if string(a.Key[:]) < string(b.Key[:]) {
			return -1
		}
		return 0
	})
	assert.Equal(t, NewMessage(expectedState), respMsg)

	conn.Close()

}

func computeStateRoot(t *testing.T, serializedState map[statekey.StateKey][]byte) crypto.Hash {
	var kvs [][2][]byte
	for key, value := range serializedState {
		kvs = append(kvs, [2][]byte{key[:], value})
	}

	stateRoot, err := trie.Merklize(kvs, 0, nil, nil)
	require.NoError(t, err)
	return stateRoot
}
