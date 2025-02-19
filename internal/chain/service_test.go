package chain

import (
	"testing"

	"github.com/eigerco/strawberry/internal/block"
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/jamtime"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCheckFinalization(t *testing.T) {
	// Create a new BlockService
	bs, err := NewBlockService()
	require.NoError(t, err)

	// Create a chain of 7 headers (0->1->2->3->4->5->6)
	// Block 1 will have 5 descendants (2,3,4,5,6) and should be finalized
	var headers []block.Header
	var hashes []crypto.Hash
	parentHash := crypto.Hash{} // Zero hash for first block

	// Create and store headers
	for i := uint32(0); i < 7; i++ {
		header := block.Header{
			TimeSlotIndex: jamtime.Timeslot(i),
			ParentHash:    parentHash,
		}

		// Store the header
		err := bs.Store.PutHeader(header)
		require.NoError(t, err)

		// Get and store the hash for next iteration
		hash, err := header.Hash()
		require.NoError(t, err)
		parentHash = hash

		headers = append(headers, header)
		hashes = append(hashes, hash)
	}

	// Add some headers as leaves
	bs.AddLeaf(hashes[6], 6) // Last one is a leaf

	// Try to finalize using the last header
	err = bs.checkFinalization(hashes[6])
	require.NoError(t, err)

	// Verify:
	// 1. Header[1] should be finalized (having 5 descendants: 2,3,4,5,6)
	// 2. Leaves should be updated
	// 3. LatestFinalized should be set to header[1]

	// Check LatestFinalized
	assert.Equal(t, hashes[1], bs.LatestFinalized.Hash)
	assert.Equal(t, headers[1].TimeSlotIndex, bs.LatestFinalized.TimeSlotIndex)

	// Check leaves - only block 6 should remain as leaf
	_, exists5 := bs.KnownLeaves[hashes[5]]
	_, exists6 := bs.KnownLeaves[hashes[6]]
	assert.False(t, exists5, "hash[5] should not be a leaf")
	assert.True(t, exists6, "hash[6] should still be a leaf")
	assert.Equal(t, 1, len(bs.KnownLeaves), "should only have one leaf")

	// Try finalizing again with same hash - should not change anything
	prevFinalized := bs.LatestFinalized
	err = bs.checkFinalization(hashes[6])
	require.NoError(t, err)
	assert.Equal(t, prevFinalized, bs.LatestFinalized, "finalization should not change on second attempt")

	// Try finalizing with non-existent hash
	err = bs.checkFinalization(crypto.Hash{1, 2, 3})
	require.NoError(t, err) // Should return nil error as per our implementation
	assert.Equal(t, prevFinalized, bs.LatestFinalized, "finalization should not change with invalid hash")
}
