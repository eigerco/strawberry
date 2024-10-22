package trie

import (
	"bytes"
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/stretchr/testify/require"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEncodeLeafNode(t *testing.T) {
	t.Run("empty value", func(t *testing.T) {
		key := StateKey{1}
		value := []byte{}
		node := EncodeLeafNode(key, value)

		assert.True(t, node.IsLeaf())
		assert.True(t, node.IsEmbeddedLeaf())
		assert.Equal(t, LeafNodeFlag, node[0])
		embeddedValueSize, err := node.GetEmbeddedValueSize()
		assert.Equal(t, 0, embeddedValueSize)
		require.NoError(t, err)

		gotKey, err := node.GetLeafKey()
		require.NoError(t, err)
		assert.Equal(t, key[:31], gotKey[:31])

		gotValue, err := node.GetLeafValue()
		require.NoError(t, err)
		assert.Equal(t, value, gotValue)
	})

	t.Run("small value", func(t *testing.T) {
		key := StateKey{2}
		value := []byte("test")
		node := EncodeLeafNode(key, value)

		assert.True(t, node.IsLeaf())
		assert.True(t, node.IsEmbeddedLeaf())
		assert.Equal(t, LeafNodeFlag|byte(len(value)), node[0])
		embeddedValueSize, err := node.GetEmbeddedValueSize()
		require.NoError(t, err)
		assert.Equal(t, len(value), embeddedValueSize)

		gotKey, err := node.GetLeafKey()
		require.NoError(t, err)
		assert.Equal(t, key[:31], gotKey[:31])

		gotValue, err := node.GetLeafValue()
		require.NoError(t, err)
		assert.Equal(t, value, gotValue)

		// Test zero-padding for small embedded values
		for i := 32 + len(value); i < 64; i++ {
			assert.Equal(t, byte(0), node[i])
		}
	})

	t.Run("32 byte value (max embedded value size)", func(t *testing.T) {
		// Test with 32 byte value
		key := StateKey{3}
		value := bytes.Repeat([]byte{1}, 32)
		node := EncodeLeafNode(key, value)

		assert.True(t, node.IsLeaf())
		assert.True(t, node.IsEmbeddedLeaf())
		assert.Equal(t, LeafNodeFlag|byte(EmbeddedValueMaxSize), node[0])
		embeddedValueSize, err := node.GetEmbeddedValueSize()
		require.NoError(t, err)
		assert.Equal(t, EmbeddedValueMaxSize, embeddedValueSize)

		gotKey, err := node.GetLeafKey()
		require.NoError(t, err)
		assert.Equal(t, key[:31], gotKey[:31])

		gotValue, err := node.GetLeafValue()
		require.NoError(t, err)
		assert.Equal(t, value, gotValue)
	})

	t.Run("large value (regular, not embedded)", func(t *testing.T) {
		// Test with large value
		key := StateKey{4}
		value := bytes.Repeat([]byte{2}, 33)
		node := EncodeLeafNode(key, value)

		assert.True(t, node.IsLeaf())
		assert.False(t, node.IsEmbeddedLeaf())
		assert.Equal(t, LeafNodeFlag|NotEmbeddedLeafFlag, node[0])

		gotKey, err := node.GetLeafKey()
		require.NoError(t, err)
		assert.Equal(t, key[:31], gotKey[:31])

		_, err = node.GetLeafValue()
		assert.Equal(t, ErrNotEmbeddedLeaf, err)

		valueHash, err := node.GetLeafValueHash()
		require.NoError(t, err)
		expectedHash := crypto.HashData(value)
		assert.Equal(t, expectedHash[:], valueHash[:])
	})

	t.Run("leaf nodes are not branch nodes and has no branch hashes", func(t *testing.T) {
		key := StateKey{1}
		value := []byte{}
		node := EncodeLeafNode(key, value)

		assert.True(t, node.IsLeaf())
		assert.False(t, node.IsBranch())

		l, r, err := node.GetBranchHashes()
		assert.Equal(t, ErrNotBranchNode, err)
		assert.Empty(t, l)
		assert.Empty(t, r)
	})
}
