package merkle

import (
	"testing"

	"github.com/eigerco/strawberry/internal/state/serialization"
	"github.com/eigerco/strawberry/internal/store"
	"github.com/eigerco/strawberry/pkg/db/pebble"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestMerklizeState_ConsistentRoot tests that the same state always produces the same Merkle root.
func TestMerklizeState_ConsistentRoot(t *testing.T) {
	kv1, err := pebble.NewKVStore()
	require.NoError(t, err)
	defer func() {
		err := kv1.Close()
		require.NoError(t, err, "failed to close kv1")
	}()

	store1 := store.NewTrie(kv1)

	kv2, err := pebble.NewKVStore()
	require.NoError(t, err)
	defer func() {
		err := kv2.Close()
		require.NoError(t, err, "failed to close kv2")
	}()

	store2 := store.NewTrie(kv2)

	// Generate identical states
	state1 := serialization.RandomState(t)
	state2 := state1

	// Test
	rootHash1, err := MerklizeState(state1, store1)
	require.NoError(t, err)

	rootHash2, err := MerklizeState(state2, store2)
	require.NoError(t, err)

	assert.Equal(t, rootHash1, rootHash2, "The same state should produce the same Merkle root.")

	// Verify that both stores contain the same nodes
	value1, err := store1.GetNode(rootHash1)
	require.NoError(t, err)
	require.NotNil(t, value1, "Root node should exist in store1")

	value2, err := store2.GetNode(rootHash2)
	require.NoError(t, err)
	require.NotNil(t, value2, "Root node should exist in store2")
}

// TestMerklizeState_DifferentState tests that different states produce different Merkle roots.
func TestMerklizeState_DifferentState(t *testing.T) {
	kv1, err := pebble.NewKVStore()
	require.NoError(t, err)
	defer func() {
		err := kv1.Close()
		require.NoError(t, err, "failed to close kv1")
	}()
	store1 := store.NewTrie(kv1)

	kv2, err := pebble.NewKVStore()
	require.NoError(t, err)
	defer func() {
		err := kv2.Close()
		require.NoError(t, err, "failed to close kv2")
	}()
	store2 := store.NewTrie(kv2)

	// Generate random states
	state1 := serialization.RandomState(t)
	state2 := serialization.RandomState(t)

	// Ensure states are different
	require.NotEqual(t, state1, state2, "Test setup failed: Generated states are identical")

	rootHash1, err := MerklizeState(state1, store1)
	require.NoError(t, err)

	rootHash2, err := MerklizeState(state2, store2)
	require.NoError(t, err)

	assert.NotEqual(t, rootHash1, rootHash2, "Different states should produce different Merkle roots.")

	// Verify that both stores contain their respective nodes
	value1, err := store1.GetNode(rootHash1)
	require.NoError(t, err)
	require.NotNil(t, value1, "Root node should exist in store1")

	value2, err := store2.GetNode(rootHash2)
	require.NoError(t, err)
	require.NotNil(t, value2, "Root node should exist in store2")
}
