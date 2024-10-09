package merkle

import (
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/stretchr/testify/require"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEncodeBranchNode(t *testing.T) {
	t.Run("encode/decode short hashes", func(t *testing.T) {
		left := crypto.Hash{1, 2, 3}
		right := crypto.Hash{32, 31, 30}

		node := EncodeBranchNode(left, right)

		assert.True(t, node.IsBranch())
		gotLeft, gotRight, err := node.GetBranchHashes()
		require.NoError(t, err)

		assert.Equal(t, left[1:], gotLeft[:31])
		assert.Equal(t, right, gotRight)
	})

	t.Run("encode/decode long hashes", func(t *testing.T) {
		left := crypto.Hash{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 255}
		right := crypto.Hash{32, 31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1}

		node := EncodeBranchNode(left, right)

		assert.True(t, node.IsBranch())
		gotLeft, gotRight, err := node.GetBranchHashes()
		require.NoError(t, err)

		assert.Equal(t, left[1:], gotLeft[:31])
		assert.Equal(t, right, gotRight)
	})

	t.Run("branch nodes should return false for leaf calls", func(t *testing.T) {
		left := crypto.Hash{1, 2, 3}
		right := crypto.Hash{4, 5, 6}
		node := EncodeBranchNode(left, right)

		assert.True(t, node.IsBranch())
		assert.False(t, node.IsLeaf())

		k, err := node.GetLeafKey()
		assert.Equal(t, ErrNotLeafNode, err)
		assert.Empty(t, k)

		v, err := node.GetLeafValue()
		assert.Equal(t, ErrNotEmbeddedLeaf, err)
		assert.Empty(t, v)

		h, err := node.GetLeafValueHash()
		assert.Equal(t, ErrNotLeafNode, err)
		assert.Empty(t, h)

		size, err := node.GetEmbeddedValueSize()
		assert.Equal(t, ErrNotEmbeddedLeaf, err)
		assert.EqualValues(t, 0, size)
	})
}
