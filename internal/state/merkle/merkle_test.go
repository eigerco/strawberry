package state

import (
	"github.com/eigerco/strawberry/internal/merkle/trie"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestMerklizeState_ConsistentRoot tests that the same state always produces the same Merkle root.
func TestMerklizeState_ConsistentRoot(t *testing.T) {
	// Create two separate DB instances
	store1, err := trie.NewDB()
	require.NoError(t, err)
	defer store1.Close()

	store2, err := trie.NewDB()
	require.NoError(t, err)
	defer store2.Close()

	// Generate identical states
	state1 := RandomState(t)
	state2 := state1

	// Test
	rootHash1, err := MerklizeState(state1, store1)
	require.NoError(t, err)

	rootHash2, err := MerklizeState(state2, store2)
	require.NoError(t, err)

	assert.Equal(t, rootHash1, rootHash2, "The same state should produce the same Merkle root.")

	// Verify that both stores contain the same nodes
	value1, err := store1.Get(rootHash1)
	require.NoError(t, err)
	require.NotNil(t, value1, "Root node should exist in store1")

	value2, err := store2.Get(rootHash2)
	require.NoError(t, err)
	require.NotNil(t, value2, "Root node should exist in store2")
}

// TestMerklizeState_DifferentState tests that different states produce different Merkle roots.
func TestMerklizeState_DifferentState(t *testing.T) {
	// Create KVStore instances
	store1, err := trie.NewDB()
	require.NoError(t, err)
	defer store1.Close()

	store2, err := trie.NewDB()
	require.NoError(t, err)
	defer store2.Close()

	// Generate random states
	state1 := RandomState(t)
	state2 := RandomState(t)

	// Ensure states are different
	require.NotEqual(t, state1, state2, "Test setup failed: Generated states are identical")

	rootHash1, err := MerklizeState(state1, store1)
	require.NoError(t, err)

	rootHash2, err := MerklizeState(state2, store2)
	require.NoError(t, err)

	assert.NotEqual(t, rootHash1, rootHash2, "Different states should produce different Merkle roots.")

	// Verify that both stores contain their respective nodes
	value1, err := store1.Get(rootHash1)
	require.NoError(t, err)
	require.NotNil(t, value1, "Root node should exist in store1")

	value2, err := store2.Get(rootHash2)
	require.NoError(t, err)
	require.NotNil(t, value2, "Root node should exist in store2")
}
