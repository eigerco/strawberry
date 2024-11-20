package trie

import (
	"bytes"
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestNewDB(t *testing.T) {
	db, err := NewDB()
	require.NoError(t, err)
	defer db.Close()

	assert.NotNil(t, db.store)
}

func TestMerklizeAndCommit(t *testing.T) {
	zeroHash := crypto.Hash(bytes.Repeat([]byte{0}, 32))

	testCases := []struct {
		name         string
		pairs        [][2][]byte
		expectedHash crypto.Hash
	}{
		{
			name:         "Empty pairs",
			pairs:        [][2][]byte{},
			expectedHash: zeroHash,
		},
		{
			name: "Single pair",
			pairs: [][2][]byte{
				{[]byte("key1"), []byte("value1")},
			},
			expectedHash: crypto.Hash{},
		},
		{
			name: "Multiple pairs",
			pairs: [][2][]byte{
				{[]byte("key1"), []byte("value1")},
				{[]byte("key2"), []byte("value2")},
			},
			expectedHash: crypto.Hash{},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			db, err := NewDB()
			require.NoError(t, err)
			defer db.Close()

			root, err := db.MerklizeAndCommit(tc.pairs)
			require.NoError(t, err)

			if len(tc.pairs) == 0 {
				assert.Equal(t, tc.expectedHash, root)
			} else {
				assert.NotEqual(t, zeroHash, root)

				// Only try to get node if we stored one
				node, err := db.Get(root)
				require.NoError(t, err)
				assert.NotNil(t, node)

				assert.True(t, node.IsBranch() || node.IsLeaf())
			}

			// Verify the root is stored correctly
			assert.Equal(t, root, db.Root())
		})
	}
}

func TestRoot(t *testing.T) {
	db, err := NewDB()
	require.NoError(t, err)
	defer db.Close()

	zeroHash := crypto.Hash(bytes.Repeat([]byte{0}, 32))

	// Initial root should be zero hash
	assert.Equal(t, zeroHash, db.Root())

	// Add some data and check root changes
	pairs := [][2][]byte{
		{[]byte("key1"), []byte("value1")},
	}
	root, err := db.MerklizeAndCommit(pairs)
	require.NoError(t, err)

	assert.NotEqual(t, zeroHash, root)
	assert.Equal(t, root, db.Root())
}

func TestGet(t *testing.T) {
	db, err := NewDB()
	require.NoError(t, err)
	defer db.Close()

	// Add some data
	pairs := [][2][]byte{
		{[]byte("key1"), []byte("value1")},
	}
	root, err := db.MerklizeAndCommit(pairs)
	require.NoError(t, err)

	// Test getting root node
	node, err := db.Get(root)
	require.NoError(t, err)
	assert.True(t, node.IsBranch() || node.IsLeaf())

	// Test getting non-existent node
	_, err = db.Get(crypto.Hash{1, 2, 3})
	assert.Error(t, err)
}

func TestNodeConsistency(t *testing.T) {
	db, err := NewDB()
	require.NoError(t, err)
	defer db.Close()

	// Create trie with data
	pairs := [][2][]byte{
		{[]byte("key1"), []byte("value1")},
	}
	root, err := db.MerklizeAndCommit(pairs)
	require.NoError(t, err)

	// Get node and verify it's valid
	node, err := db.Get(root)
	require.NoError(t, err)
	assert.True(t, node.IsBranch() || node.IsLeaf())

	// Commit same data again
	newRoot, err := db.MerklizeAndCommit(pairs)
	require.NoError(t, err)

	// Verify roots are same
	assert.Equal(t, root, newRoot)

	// Get node again and verify it's valid
	newNode, err := db.Get(newRoot)
	require.NoError(t, err)
	assert.True(t, newNode.IsBranch() || newNode.IsLeaf())

	// Verify nodes are the same
	if node.IsBranch() {
		assert.True(t, newNode.IsBranch())
		leftOld, rightOld, err := node.GetBranchHashes()
		require.NoError(t, err)
		leftNew, rightNew, err := newNode.GetBranchHashes()
		require.NoError(t, err)
		assert.Equal(t, leftOld, leftNew)
		assert.Equal(t, rightOld, rightNew)
	} else {
		assert.True(t, newNode.IsLeaf())
		keyOld, err := node.GetLeafKey()
		require.NoError(t, err)
		keyNew, err := newNode.GetLeafKey()
		require.NoError(t, err)
		assert.Equal(t, keyOld, keyNew)
	}
}

func TestConcurrency(t *testing.T) {
	db, err := NewDB()
	require.NoError(t, err)
	defer db.Close()

	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func(i int) {
			pairs := [][2][]byte{
				{[]byte("key"), []byte{byte(i)}},
			}
			_, err := db.MerklizeAndCommit(pairs)
			assert.NoError(t, err)
			done <- true
		}(i)
	}

	for i := 0; i < 10; i++ {
		<-done
	}
}
