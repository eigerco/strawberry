package store

import (
	"testing"

	"github.com/eigerco/strawberry/internal/block"
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/jamtime"
	"github.com/eigerco/strawberry/internal/testutils"
	"github.com/eigerco/strawberry/pkg/db/pebble"
	"github.com/eigerco/strawberry/pkg/serialization/codec/jam"
	"github.com/stretchr/testify/require"
)

func Test_PutGetBlock(t *testing.T) {
	chain := newStore(t)
	header := block.Header{
		ParentHash: testutils.RandomHash(t),
	}
	hb, err := jam.Marshal(header)
	require.NoError(t, err)
	hh := crypto.HashData(hb)
	block := block.Block{
		Header: header,
	}
	err = chain.PutBlock(block)
	require.NoError(t, err)
	resultBlock, err := chain.GetBlock(hh)
	require.NoError(t, err)
	require.Equal(t, header.ParentHash, resultBlock.Header.ParentHash)
}

func Test_GetBlockNotFound(t *testing.T) {
	chain := newStore(t)
	_, err := chain.GetBlock(testutils.RandomHash(t))
	require.Error(t, err)
	require.Equal(t, ErrBlockNotFound, err)
}

func Test_Close(t *testing.T) {
	chain := newStore(t)
	err := chain.Close()
	require.NoError(t, err)
	err = chain.Close()
	// Closing a closed chain should have no effect/error
	require.NoError(t, err)
}

func Test_ChainClosed(t *testing.T) {
	chain := newStore(t)
	chain.Close()
	_, err := chain.GetBlock(testutils.RandomHash(t))
	require.Error(t, err)
	require.Equal(t, ErrChainClosed, err)
}

func Test_FindChildren(t *testing.T) {
	chain := newStore(t)

	// Create parent block
	parentBlock := block.Block{
		Header: block.Header{
			ParentHash: crypto.Hash{},
		},
	}
	err := chain.PutBlock(parentBlock)
	require.NoError(t, err)

	ph, err := jam.Marshal(parentBlock.Header)
	require.NoError(t, err)

	// Create child blocks
	childBlock1 := block.Block{
		Header: block.Header{
			ParentHash: crypto.HashData(ph),
			// Random data so that the block hash is unique
			ExtrinsicHash: testutils.RandomHash(t),
		},
	}
	err = chain.PutBlock(childBlock1)
	require.NoError(t, err)

	childBlock2 := block.Block{
		Header: block.Header{
			ParentHash: crypto.HashData(ph),
			// Random data so that the block hash is unique
			ExtrinsicHash: testutils.RandomHash(t),
		},
	}
	err = chain.PutBlock(childBlock2)
	require.NoError(t, err)

	// Find children of parent block
	children, err := chain.FindChildren(crypto.HashData(ph))
	require.NoError(t, err)
	require.Len(t, children, 2)
	require.ElementsMatch(t, []block.Block{childBlock1, childBlock2}, children)
}

func Test_FindChildren_NoChildren(t *testing.T) {
	chain := newStore(t)

	// Create parent block
	parentBlock := block.Block{
		Header: block.Header{
			ParentHash: crypto.Hash{},
		},
	}
	err := chain.PutBlock(parentBlock)
	require.NoError(t, err)

	ph, err := jam.Marshal(parentBlock.Header)
	require.NoError(t, err)
	// Find children of parent block (should be none)
	children, err := chain.FindChildren(crypto.HashData(ph))
	require.NoError(t, err)
	require.Empty(t, children)
}

func Test_FindChildren_ChainClosed(t *testing.T) {
	chain := newStore(t)
	chain.Close()

	_, err := chain.FindChildren(testutils.RandomHash(t))
	require.Error(t, err)
	require.Equal(t, ErrChainClosed, err)
}

func Test_GetBlockSequence_Ascending(t *testing.T) {
	chain := newStore(t)

	// Create a sequence of blocks
	blocks := createNumOfRandomBlocks(5, t)
	for _, b := range blocks {
		err := chain.PutBlock(b)
		require.NoError(t, err)
	}

	// Get the hash of the first block
	startHash, err := blocks[0].Header.Hash()
	require.NoError(t, err)

	// Retrieve the sequence in ascending order
	sequence, err := chain.GetBlockSequence(startHash, true, 4)
	require.NoError(t, err)
	require.Len(t, sequence, 4)
	require.Equal(t, blocks[1:], sequence) // Should exclude the start block
}

func Test_GetBlockSequence_AscendingRequestTooMany(t *testing.T) {
	chain := newStore(t)

	// Create a sequence of blocks
	blocks := createNumOfRandomBlocks(5, t)
	for _, b := range blocks {
		err := chain.PutBlock(b)
		require.NoError(t, err)
	}

	// Get the hash of the first block
	startHash, err := blocks[0].Header.Hash()
	require.NoError(t, err)

	// Request more blocks than available
	sequence, err := chain.GetBlockSequence(startHash, true, 10)
	require.NoError(t, err)
	require.Len(t, sequence, 4)
	require.Equal(t, blocks[1:], sequence) // Should exclude the start block
}

func Test_GetBlockSequence_Descending(t *testing.T) {
	chain := newStore(t)

	// Create a sequence of blocks
	blocks := createNumOfRandomBlocks(5, t)
	for _, b := range blocks {
		err := chain.PutBlock(b)
		require.NoError(t, err)
	}

	// Get the hash of the last block
	startHash, err := blocks[len(blocks)-1].Header.Hash()
	require.NoError(t, err)

	// Retrieve the sequence in descending order
	sequence, err := chain.GetBlockSequence(startHash, false, 5)
	require.NoError(t, err)
	require.Len(t, sequence, 5) // Should include the start block
	for i := range sequence {
		// The sequence should be in reverse order
		require.Equal(t, blocks[len(blocks)-1-i], sequence[i])
	}
}

func Test_GetBlockSequence_DescendingRequestTooMany(t *testing.T) {
	chain := newStore(t)

	// Create a sequence of blocks
	blocks := createNumOfRandomBlocks(5, t)
	for _, b := range blocks {
		err := chain.PutBlock(b)
		require.NoError(t, err)
	}

	// Get the hash of the last block
	startHash, err := blocks[len(blocks)-1].Header.Hash()
	require.NoError(t, err)

	// Retrieve the sequence in descending order
	sequence, err := chain.GetBlockSequence(startHash, false, 10)
	require.NoError(t, err)
	require.Len(t, sequence, 5) // Should include the start block
	for i := range sequence {
		// The sequence should be in reverse order
		require.Equal(t, blocks[len(blocks)-1-i], sequence[i])
	}
}

func Test_GetBlockSequence_ChainClosed(t *testing.T) {
	chain := newStore(t)
	chain.Close()

	_, err := chain.GetBlockSequence(testutils.RandomHash(t), true, 5)
	require.Error(t, err)
	require.Equal(t, ErrChainClosed, err)
}

// CreateRandomBlock generates a random block for testing purposes
func createRandomBlock(parentHash crypto.Hash, slot jamtime.Timeslot, t *testing.T) block.Block {
	// Generate a random block header
	header := block.Header{
		ParentHash:    parentHash, // Parent hash (passed as argument)
		TimeSlotIndex: slot,       // Slot (passed as argument)
		// Populate other header fields with random data
		PriorStateRoot: testutils.RandomHash(t),
		ExtrinsicHash:  testutils.RandomHash(t),
	}
	// Return the random block
	return block.Block{
		Header: header,
	}
}

func createNumOfRandomBlocks(num int, t *testing.T) []block.Block {
	blocks := []block.Block{}
	prevB := createRandomBlock(crypto.Hash{}, jamtime.MinTimeslot, t)
	hh, _ := prevB.Header.Hash()
	blocks = append(blocks, prevB)
	for range num - 1 {
		b := createRandomBlock(hh, prevB.Header.TimeSlotIndex+1, t)
		blocks = append(blocks, b)
		prevB = b
		h, _ := prevB.Header.Bytes()
		hh = crypto.HashData(h)
	}
	return blocks
}

func newStore(t *testing.T) *Chain {
	kvStore, err := pebble.NewKVStore()
	require.NoError(t, err)
	chain := NewChain(kvStore)
	return chain
}
