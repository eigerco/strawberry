package state

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestMerklizeState_ConsistentRoot tests that the same state always produces the same Merkle root.
func TestMerklizeState_ConsistentRoot(t *testing.T) {
	state1 := RandomState(t)
	state2 := state1 // Ensure the state is identical

	rootHash1, err := MerklizeState(state1)
	require.NoError(t, err)
	rootHash2, err := MerklizeState(state2)
	require.NoError(t, err)

	assert.Equal(t, rootHash1, rootHash2, "The same state should produce the same Merkle root.")
}

// TestMerklizeState_DifferentState tests that different states produce different Merkle roots.
func TestMerklizeState_DifferentState(t *testing.T) {
	state1 := RandomState(t)
	state2 := RandomState(t)

	// Ensure states are different
	require.NotEqual(t, state1, state2)

	rootHash1, err := MerklizeState(state1)
	require.NoError(t, err)
	rootHash2, err := MerklizeState(state2)
	require.NoError(t, err)

	assert.NotEqual(t, rootHash1, rootHash2, "Different states should produce different Merkle roots.")
}

// TestGetBit tests the getBit utility function.
func TestGetBit(t *testing.T) {
	byteSeq := []byte{0xA2} // 10100010 in binary

	// Test individual bits
	assert.Equal(t, byte(1), getBit(byteSeq, 0), "The first bit should be 1.")
	assert.Equal(t, byte(0), getBit(byteSeq, 1), "The second bit should be 0.")
	assert.Equal(t, byte(1), getBit(byteSeq, 2), "The third bit should be 1.")
	assert.Equal(t, byte(0), getBit(byteSeq, 3), "The fourth bit should be 0.")
	assert.Equal(t, byte(0), getBit(byteSeq, 4), "The fifth bit should be 0.")
	assert.Equal(t, byte(0), getBit(byteSeq, 5), "The sixth bit should be 0.")
	assert.Equal(t, byte(1), getBit(byteSeq, 6), "The seventh bit should be 1.")
	assert.Equal(t, byte(0), getBit(byteSeq, 7), "The eighth bit should be 0.")
}
