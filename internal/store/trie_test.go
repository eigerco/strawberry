package store

import (
	"bytes"
	"testing"

	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/pkg/db/pebble"
	"github.com/stretchr/testify/require"
)

func TestComplex(t *testing.T) {
	// Keys designed to create a 2-level deep branch structure
	// keyLL: 00... path
	var keyLL = bytes.Repeat([]byte{0x01}, 32) // Binary Prefix: 00000001...
	// keyLR: 01... path
	var keyLR = bytes.Repeat([]byte{0x41}, 32) // Binary Prefix: 01000001...
	// keyRL: 10... path
	var keyRL = bytes.Repeat([]byte{0x81}, 32) // Binary Prefix: 10000001...
	// keyRR: 11... path
	var keyRR = bytes.Repeat([]byte{0xC1}, 32) // Binary Prefix: 11000001...

	// Values designed to create both Embedded and Regular leaves
	// <= 32 bytes for Embedded Leaf
	var valueLL_small = []byte("small value for Left-Left")
	var valueRR_small = []byte("small value for Right-Right")

	// > 32 bytes for Regular Leaf
	var valueLR_large = []byte("this is a large value for Left-Right path, exceeding 32 bytes")
	var valueRL_large = []byte("this is another large value, for Right-Left path, also > 32 bytes")

	// The final list of pairs to pass to MerklizeAndCommit
	var pairs = [][2][]byte{
		{keyLL, valueLL_small}, // Goes 0 -> 0. Embedded Leaf.
		{keyLR, valueLR_large}, // Goes 0 -> 1. Regular Leaf.
		{keyRL, valueRL_large}, // Goes 1 -> 0. Regular Leaf.
		{keyRR, valueRR_small}, // Goes 1 -> 1. Embedded Leaf.
	}
	db, err := pebble.NewKVStore()
	require.NoError(t, err)
	defer func() {
		err := db.Close()
		require.NoError(t, err, "failed to close db")
	}()

	tr := NewTrie(db)

	root, err := tr.MerklizeAndCommit(pairs)
	require.NoError(t, err)
	node, err := tr.GetNode(root)
	require.NoError(t, err)
	require.True(t, node.IsBranch())
	// Check the left branch
	leftHash, rightHash, err := node.GetBranchHashes()
	require.NoError(t, err)
	//print left hash first byte
	require.NotEqual(t, crypto.Hash{}, leftHash)
	require.NotEqual(t, crypto.Hash{}, rightHash)
	// Check the left branch node
	leftNode, err := tr.GetNode(leftHash)
	require.NoError(t, err)
	require.True(t, leftNode.IsBranch())
	// Check the left-left node
	leftLeftHash, leftRightHash, err := leftNode.GetBranchHashes()
	require.NoError(t, err)
	require.NotEqual(t, crypto.Hash{}, leftLeftHash)
	require.NotEqual(t, crypto.Hash{}, leftRightHash)
	// Check the left-left node
	leftLeftNode, err := tr.GetNode(leftLeftHash)
	require.NoError(t, err)
	require.True(t, leftLeftNode.IsLeaf())
	// Check the left-left node key
	key, err := leftLeftNode.GetLeafKey()
	require.NoError(t, err)
	require.Equal(t, keyLL[:31], key[:31])
	// Check the left-left node value
	value, err := leftLeftNode.GetLeafValue()

	require.NoError(t, err)
	require.Equal(t, valueLL_small, value)
	// Check the left-right node
	leftRightNode, err := tr.GetNode(leftRightHash)
	require.NoError(t, err)
	require.True(t, leftRightNode.IsLeaf())
	// Check the left-right node key
	key, err = leftRightNode.GetLeafKey()
	require.NoError(t, err)
	require.Equal(t, keyLR[:31], key[:31])
	// Check the left-right node value
	valueHash, err := leftRightNode.GetLeafValueHash()
	require.NoError(t, err)
	v, err := tr.getValue(valueHash)
	require.NoError(t, err)
	require.Equal(t, valueLR_large, v)
}

func TestNodeRefCountAndDelete(t *testing.T) {
	// Setup the same test data as in TestComplex
	// Keys designed to create a 2-level deep branch structure
	var keyLL = bytes.Repeat([]byte{0x01}, 32) // Binary Prefix: 00000001...
	var keyLR = bytes.Repeat([]byte{0x41}, 32) // Binary Prefix: 01000001...
	var keyRL = bytes.Repeat([]byte{0x81}, 32) // Binary Prefix: 10000001...
	var keyRR = bytes.Repeat([]byte{0xC1}, 32) // Binary Prefix: 11000001...

	// Values
	var valueLL_small = []byte("small value for Left-Left")
	var valueRR_small = []byte("small value for Right-Right")
	var valueLR_large = []byte("this is a large value for Left-Right path, exceeding 32 bytes")
	var valueRL_large = []byte("this is another large value, for Right-Left path, also > 32 bytes")

	// The final list of pairs
	var pairs = [][2][]byte{
		{keyLL, valueLL_small}, // Goes 0 -> 0. Embedded Leaf.
		{keyLR, valueLR_large}, // Goes 0 -> 1. Regular Leaf.
		{keyRL, valueRL_large}, // Goes 1 -> 0. Regular Leaf.
		{keyRR, valueRR_small}, // Goes 1 -> 1. Embedded Leaf.
	}

	db, err := pebble.NewKVStore()
	require.NoError(t, err)
	defer func() {
		err := db.Close()
		require.NoError(t, err, "failed to close db")
	}()

	tr := NewTrie(db)

	// Create the trie
	root, err := tr.MerklizeAndCommit(pairs)
	require.NoError(t, err)

	// Verify the trie exists
	exists, err := tr.TrieExists(root)
	require.NoError(t, err)
	require.True(t, exists)

	// Get the root node
	rootNode, err := tr.GetNode(root)
	require.NoError(t, err)
	require.True(t, rootNode.IsBranch())

	// Get the left and right branches
	leftHash, rightHash, err := rootNode.GetBranchHashes()
	require.NoError(t, err)
	require.NotEqual(t, crypto.Hash{}, leftHash)
	require.NotEqual(t, crypto.Hash{}, rightHash)

	// Check ref counts for root and direct children
	// The root should have a ref count of 1
	refCount, err := tr.GetNodeRefCount(root)
	require.NoError(t, err)
	require.Equal(t, uint64(1), refCount, "Root node should have ref count of 1")

	// The left branch should have a ref count of 1
	refCount, err = tr.GetNodeRefCount(leftHash)
	require.NoError(t, err)
	require.Equal(t, uint64(1), refCount, "Left branch should have ref count of 1")

	// The right branch should have a ref count of 1
	refCount, err = tr.GetNodeRefCount(rightHash)
	require.NoError(t, err)
	require.Equal(t, uint64(1), refCount, "Right branch should have ref count of 1")

	// Create a second trie that shares some nodes with the first one
	// We'll modify just one leaf to create a different but overlapping trie
	var pairs2 = [][2][]byte{
		{keyLL, valueLL_small},       // Same as before
		{keyLR, valueLR_large},       // Same as before
		{keyRL, valueRL_large},       // Same as before
		{keyRR, []byte("new value")}, // Different value for RR
	}

	// Create the second trie
	root2, err := tr.MerklizeAndCommit(pairs2)
	require.NoError(t, err)
	require.NotEqual(t, root, root2, "Second trie should have a different root")

	// The shared nodes should now have a ref count of 2
	// Get the second trie's root node
	root2Node, err := tr.GetNode(root2)
	require.NoError(t, err)

	// Get its left child
	leftHash2, _, err := root2Node.GetBranchHashes()
	require.NoError(t, err)

	// The left branch should be the same in both tries since we didn't change those nodes
	require.Equal(t, leftHash, leftHash2, "Left branch should be shared between tries")

	// Check ref count for the shared left branch (should be 2)
	refCount, err = tr.GetNodeRefCount(leftHash)
	require.NoError(t, err)
	require.Equal(t, uint64(2), refCount, "Shared left branch should have ref count of 2")

	// Now delete the first trie
	err = tr.DeleteTrie(root)
	require.NoError(t, err)

	// Verify the first trie no longer exists
	exists, err = tr.TrieExists(root)
	require.NoError(t, err)
	require.False(t, exists, "First trie should no longer exist")

	// But the second trie should still exist
	exists, err = tr.TrieExists(root2)
	require.NoError(t, err)
	require.True(t, exists, "Second trie should still exist")

	// The shared left branch should now have a ref count of 1
	refCount, err = tr.GetNodeRefCount(leftHash)
	require.NoError(t, err)
	require.Equal(t, uint64(1), refCount, "After deleting first trie, shared left branch should have ref count of 1")

	// Now delete the second trie
	err = tr.DeleteTrie(root2)
	require.NoError(t, err)

	// Verify the second trie no longer exists
	exists, err = tr.TrieExists(root2)
	require.NoError(t, err)
	require.False(t, exists, "Second trie should no longer exist")

	// The left branch should no longer exist
	_, err = tr.GetNode(leftHash)
	require.Error(t, err, "Left branch should be deleted after both tries are removed")
}
