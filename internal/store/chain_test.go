package store

import (
	"testing"

	"github.com/eigerco/strawberry/internal/block"
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/jamtime"
	"github.com/eigerco/strawberry/internal/testutils"
	"github.com/eigerco/strawberry/pkg/db/pebble"
	"github.com/eigerco/strawberry/pkg/serialization/codec/jam"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPutAndGetHeader(t *testing.T) {
	db, err := pebble.NewKVStore()
	require.NoError(t, err)

	chain := NewChain(db)
	defer chain.Close()

	// Create a parent header with a zero ParentHash (genesis block)
	parentHeader := block.Header{
		ParentHash:    crypto.Hash{}, // Genesis block has no parent
		TimeSlotIndex: jamtime.Timeslot(1),
	}

	// Store the parent header
	err = chain.PutHeader(parentHeader)
	require.NoError(t, err)

	// Calculate the hash of the parent header
	encodedParentHeader, err := jam.Marshal(parentHeader)
	require.NoError(t, err)
	parentHeaderHash := crypto.HashData(encodedParentHeader)

	// Create a child header referencing the parent header
	childHeader := block.Header{
		ParentHash:    parentHeaderHash,
		TimeSlotIndex: parentHeader.TimeSlotIndex + 1,
	}

	// Store the child header
	err = chain.PutHeader(childHeader)
	require.NoError(t, err)

	// Retrieve the ancestor (parent header) of the child header
	ancestorHeader, err := chain.GetHeader(childHeader.ParentHash)
	require.NoError(t, err)
	require.NotEmpty(t, ancestorHeader, "Ancestor should be found")

	// Verify that the retrieved ancestor matches the original parent header
	assert.Equal(t, parentHeader.ParentHash, ancestorHeader.ParentHash, "ParentHash should match")
	assert.Equal(t, parentHeader.TimeSlotIndex, ancestorHeader.TimeSlotIndex, "TimeSlotIndex should match")
}

func TestGetNonExistentAncestor(t *testing.T) {
	db, err := pebble.NewKVStore()
	require.NoError(t, err)

	chain := NewChain(db)
	defer chain.Close()

	header := block.Header{
		ParentHash: crypto.Hash{1, 2, 3}, // This hash doesn't exist in store
	}

	// Try to get a non-existent ancestor
	retrieved, err := chain.GetHeader(header.ParentHash)
	require.ErrorIs(t, err, ErrHeaderNotFound)
	assert.Empty(t, retrieved)
}

func Test_FindHeader_ByParentHash(t *testing.T) {
	chain := newStore(t)
	defer chain.Close()

	parentHash := testutils.RandomHash(t)
	header1 := block.Header{
		ParentHash:     parentHash,
		TimeSlotIndex:  jamtime.Timeslot(1),
		PriorStateRoot: testutils.RandomHash(t),
	}
	header2 := block.Header{
		ParentHash:     testutils.RandomHash(t), // Different parent hash
		TimeSlotIndex:  jamtime.Timeslot(2),
		PriorStateRoot: testutils.RandomHash(t),
	}

	// Store both headers
	require.NoError(t, chain.PutHeader(header1))
	require.NoError(t, chain.PutHeader(header2))

	// Find header by parent hash
	found, err := chain.FindHeader(func(h block.Header) bool {
		return h.ParentHash == parentHash
	})
	require.NoError(t, err)
	require.Equal(t, header1, found)
}

func Test_FindHeader_ByTimeSlot(t *testing.T) {
	chain := newStore(t)
	defer chain.Close()

	targetSlot := jamtime.Timeslot(5)
	header1 := block.Header{
		ParentHash:     testutils.RandomHash(t),
		TimeSlotIndex:  targetSlot,
		PriorStateRoot: testutils.RandomHash(t),
	}
	header2 := block.Header{
		ParentHash:     testutils.RandomHash(t),
		TimeSlotIndex:  jamtime.Timeslot(6),
		PriorStateRoot: testutils.RandomHash(t),
	}

	// Store both headers
	require.NoError(t, chain.PutHeader(header1))
	require.NoError(t, chain.PutHeader(header2))

	// Find header by timeslot
	found, err := chain.FindHeader(func(h block.Header) bool {
		return h.TimeSlotIndex == targetSlot
	})
	require.NoError(t, err)
	require.Equal(t, header1, found)
}

func Test_FindHeader_NotFound(t *testing.T) {
	chain := newStore(t)
	defer chain.Close()

	header := block.Header{
		ParentHash:     testutils.RandomHash(t),
		TimeSlotIndex:  jamtime.Timeslot(1),
		PriorStateRoot: testutils.RandomHash(t),
	}
	require.NoError(t, chain.PutHeader(header))

	// Try to find non-existent header
	h, err := chain.FindHeader(func(h block.Header) bool {
		return h.TimeSlotIndex == jamtime.Timeslot(999)
	})
	require.NoError(t, err)
	require.Empty(t, h)
}

func Test_FindHeader_ChainClosed(t *testing.T) {
	chain := newStore(t)
	chain.Close()

	_, err := chain.FindHeader(func(h block.Header) bool {
		return true
	})
	require.ErrorIs(t, err, ErrChainClosed)
}

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
