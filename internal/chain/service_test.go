package chain

import (
	"fmt"
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

	// Create a chain of 6 headers (0->1->2->3->4->5)
	var headers []block.Header
	var hashes []crypto.Hash
	parentHash := crypto.Hash{} // Zero hash for first block

	// Create and store headers
	for i := uint32(0); i < 6; i++ {
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
	for i, h := range hashes {
		fmt.Printf("hashes[%d]: %v\n", i, h)
	}

	// Add some headers as leaves
	bs.AddLeaf(hashes[5], 5) // Last one

	// Try to finalize using the last header
	err = bs.checkFinalization(hashes[5])
	require.NoError(t, err)

	// Verify:
	// 1. Header[1] should be finalized (being the earliest in the 5-chain)
	// 2. Leaves should be updated (4 and 5 should no longer be leaves)
	// 3. LatestFinalized should be set to header[1]

	// Check LatestFinalized
	assert.Equal(t, hashes[1], bs.LatestFinalized.Hash)
	assert.Equal(t, headers[1].TimeSlotIndex, bs.LatestFinalized.TimeSlotIndex)

	// Check leaves were removed
	_, exists4 := bs.KnownLeaves[hashes[4]]
	_, exists5 := bs.KnownLeaves[hashes[5]]
	assert.False(t, exists4, "hash[4] should not be a leaf anymore")
	assert.True(t, exists5, "hash[5] should be a leaf")
	assert.Equal(t, 1, len(bs.KnownLeaves), "should only have one leaf")
	// Try finalizing again with same hash - should not change anything
	prevFinalized := bs.LatestFinalized
	err = bs.checkFinalization(hashes[5])
	require.NoError(t, err)
	assert.Equal(t, prevFinalized, bs.LatestFinalized, "finalization should not change on second attempt")

	// Try finalizing with non-existent hash
	err = bs.checkFinalization(crypto.Hash{1, 2, 3})
	require.NoError(t, err) // Should return nil error as per our implementation
	assert.Equal(t, prevFinalized, bs.LatestFinalized, "finalization should not change with invalid hash")
}
