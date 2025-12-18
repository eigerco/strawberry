package store

import (
	"bytes"
	"fmt"
	"strings"
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

func TestCE129GetKeyValueRange(t *testing.T) {
	// Setup test data
	keys, values := setupTestKeys()

	// Setup DB and Trie
	db, err := pebble.NewKVStore()
	require.NoError(t, err)
	defer func() {
		err := db.Close()
		require.NoError(t, err)
	}()

	tr := NewTrie(db)

	// Prepare key-value pairs
	pairs := make([][2][]byte, len(keys))
	for i := range keys {
		pairs[i] = [2][]byte{keys[i], values[i]}
	}

	// Merklize and commit
	root, err := tr.MerklizeAndCommit(pairs)
	require.NoError(t, err)

	// Helper function to convert to 31-byte keys
	toKey31 := func(b []byte) [31]byte {
		var key [31]byte
		copy(key[:], b[:31])
		return key
	}

	// These are the size requirements for individual keys
	// Used to create test cases with accurate size expectations
	keySizes := []uint32{
		251, // key 0
		251, // key 1
		315, // key 2
		315, // key 3
		315, // key 4
		379, // key 5
		379, // key 6
	}

	// Precalculated sizes for different ranges of keys
	// Used to test boundary conditions precisely
	sizeData := map[string]uint32{
		"full_range": 813, // Size of all 7 keys
		"range_0_1":  366, // Size of keys 0-1
		"range_0_2":  545, // Size of keys 0-2
		"range_2_4":  545, // Size of keys 2-4
		"range_4_6":  545, // Size of keys 4-6
		"range_3_6":  660, // Size of keys 3-6
	}

	// Comprehensive test cases with explicit boundary conditions
	testCases := []struct {
		name              string
		startKey          int
		endKey            int
		maxSize           uint32
		expectedPairs     int
		shouldExceedLimit bool
	}{
		// Basic unlimited size test
		// Verifies the function returns all keys when size is not a constraint
		{
			name:              "Full range with unlimited size",
			startKey:          0,
			endKey:            6,
			maxSize:           sizeData["full_range"] + 100, // Plenty of room
			expectedPairs:     7,
			shouldExceedLimit: false,
		},

		// Single-item exemption
		// Verifies that a single item is always returned even if it exceeds the size limit
		{
			name:              "Single key with very small size limit",
			startKey:          2,
			endKey:            2,
			maxSize:           10, // Much smaller than any key
			expectedPairs:     1,  // Should still return 1 key due to single-item exemption
			shouldExceedLimit: true,
		},

		// Exact size for 1 key
		// Tests the boundary condition where the size limit exactly matches 1 key
		{
			name:              "Exact size for 1 key",
			startKey:          0,
			endKey:            6,
			maxSize:           keySizes[0],
			expectedPairs:     1,
			shouldExceedLimit: false,
		},

		// Just under size for 2 keys
		// Tests that with size just below what's needed for 2 keys, only 1 is returned
		{
			name:              "Just below size for 2 keys",
			startKey:          0,
			endKey:            6,
			maxSize:           sizeData["range_0_1"] - 1,
			expectedPairs:     1,
			shouldExceedLimit: false,
		},

		// Exact size for 2 keys
		// Tests the boundary condition where the size limit exactly matches 2 keys
		{
			name:              "Exact size for 2 keys",
			startKey:          0,
			endKey:            6,
			maxSize:           sizeData["range_0_1"],
			expectedPairs:     2,
			shouldExceedLimit: false,
		},

		// Just above size for 2 keys
		// Tests that adding 1 byte above 2-key size doesn't get a 3rd key
		{
			name:              "Just above size for 2 keys",
			startKey:          0,
			endKey:            6,
			maxSize:           sizeData["range_0_1"] + 1,
			expectedPairs:     2,
			shouldExceedLimit: false,
		},

		// Just below size for 3 keys
		// Key boundary test - size limit is 1 byte less than needed for 3 keys
		{
			name:              "Just below size for 3 keys",
			startKey:          0,
			endKey:            6,
			maxSize:           sizeData["range_0_2"] - 1,
			expectedPairs:     2, // Should return 2 keys instead of 3
			shouldExceedLimit: false,
		},

		// Exact size for 3 keys
		// Tests the boundary condition where the size limit exactly matches 3 keys
		{
			name:              "Exact size for 3 keys",
			startKey:          0,
			endKey:            6,
			maxSize:           sizeData["range_0_2"],
			expectedPairs:     3,
			shouldExceedLimit: false,
		},

		// Middle range exact size
		// Tests that ranges in the middle of the key space work correctly
		{
			name:              "Middle range with exact size limit",
			startKey:          2,
			endKey:            4,
			maxSize:           sizeData["range_2_4"],
			expectedPairs:     3, // Should return keys 2,3,4
			shouldExceedLimit: false,
		},

		// Middle range just below size
		// Tests middle ranges with size constraints
		{
			name:              "Middle range with size limit minus 1 byte",
			startKey:          2,
			endKey:            4,
			maxSize:           sizeData["range_2_4"] - 1,
			expectedPairs:     2, // Should return 2 keys instead of 3
			shouldExceedLimit: false,
		},

		// Right side range
		// Tests ranges toward the end of the key space which have different structure
		{
			name:              "Right side range with exact size limit",
			startKey:          3,
			endKey:            6,
			maxSize:           sizeData["range_3_6"],
			expectedPairs:     4, // Should return keys 3,4,5,6
			shouldExceedLimit: false,
		},

		// Size limit between key sizes
		// Tests what happens when the size limit falls between exact key boundaries
		{
			name:              "Range with size limit between key sizes",
			startKey:          0,
			endKey:            6,
			maxSize:           (keySizes[0] + sizeData["range_0_1"]) / 2,
			expectedPairs:     1, // Should return just 1 key
			shouldExceedLimit: false,
		},

		// Empty range
		// Tests what happens with an empty range (start key > end key)
		{
			name:              "Empty range (start key > end key)",
			startKey:          3,
			endKey:            1,
			maxSize:           1000,
			expectedPairs:     0, // Should return no keys
			shouldExceedLimit: false,
		},
	}

	// Run all test cases
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			startKey31 := toKey31(keys[tc.startKey])
			endKey31 := toKey31(keys[tc.endKey])

			// Run the query with the new return type
			result, err := tr.FetchStateTrieRange(root, startKey31, endKey31, tc.maxSize)
			require.NoError(t, err)

			// Check count of key-value pairs
			require.Equal(t, tc.expectedPairs, len(result.Pairs),
				"Expected %d key-value pairs", tc.expectedPairs)

			// Verify keys are ordered (if there are multiple keys)
			if len(result.Pairs) > 1 {
				for i := 1; i < len(result.Pairs); i++ {
					require.True(t, bytes.Compare(result.Pairs[i-1].Key[:], result.Pairs[i].Key[:]) < 0,
						"Keys not in ascending order")
				}
			}

			// Calculate the total size of the response
			totalSize, err := calculateResponseSize(result.Pairs, result.BoundaryNodes)
			require.NoError(t, err)

			if testing.Verbose() {
				t.Logf("Response size: %d bytes (limit: %d)", totalSize, tc.maxSize)
			}

			// Verify size constraints
			if tc.shouldExceedLimit {
				// Special case: single key-value pair can exceed the max size
				require.Greater(t, totalSize, tc.maxSize,
					"Expected size to exceed maxSize due to single-item exemption")
			} else if len(result.Pairs) > 0 {
				// Normal case: response should not exceed max size
				require.LessOrEqual(t, totalSize, tc.maxSize,
					"Total size (%d) exceeds maxSize (%d)", totalSize, tc.maxSize)
			}

			// Verify boundary nodes are present and form valid paths
			if len(result.Pairs) > 0 {
				require.NotEmpty(t, result.BoundaryNodes, "Boundary nodes should not be empty when keys are returned")
			}
		})
	}
}

// setupTestKeys creates test keys and values with a predictable binary trie structure
/*
                          			  ROOT
                 	   /           	             \
           LEFT BRANCH(0)    		    		 RIGHT BRANCH(1)
            /        \       		         /       			   \
      0x01(00)      0x41(01) 		 LEFT BRANCH(10) 			RIGHT RIGHT BRANCH(11)
                      		         /          \    			    /          \
                      		   0x81(100)     0xA1(101) 		0xC1(110)  RIGHT RIGHT RIGHT BRANCH(111)
                      		                             		         /          \
                      		                       	     		  0xE1(1110)     0xFF(1111)

Keys:
0x01 - 0000 0001 - Key 1 - Path: 00 (Left, Left)
0x41 - 0100 0001 - Key 2 - Path: 01 (Left, Right)
0x81 - 1000 0001 - Key 3 - Path: 100 (Right, Left, Left)
0xA1 - 1010 0001 - Key 4 - Path: 101 (Right, Left, Right)
0xC1 - 1100 0001 - Key 5 - Path: 110 (Right, Right, Left)
0xE1 - 1110 0001 - Key 6 - Path: 1110 (Right, Right, Right, Left)
0xFF - 1111 1111 - Key 7 - Path: 1111 (Right, Right, Right, Right)
*/

func setupTestKeys() ([][]byte, [][]byte) {
	// Create keys with a structure that ensures a binary tree with various depths
	// Keys are designed to create a deeper structure on the right side
	keys := [][]byte{
		{0x01, 0x01, 0x01}, // 0000 0001 ... - Path starts with 0 (Left, Left branch)
		{0x41, 0x01, 0x01}, // 0100 0001 ... - Path starts with 0 (Left, Right branch)
		{0x81, 0x01, 0x01}, // 1000 0001 ... - Path starts with 1 (Right, Left branch)
		{0xA1, 0x01, 0x01}, // 1010 0001 ... - Path starts with 1 (Right, Left, Right branch)
		{0xC1, 0x01, 0x01}, // 1100 0001 ... - Path starts with 1 (Right, Right, Left branch)
		{0xE1, 0x01, 0x01}, // 1110 0001 ... - Path starts with 1 (Right. Right, Right, Left branch)
		{0xFF, 0x01, 0x01}, // 1111 1111 ... - Path starts with 1 (Right, Right, Right, Right branch)
	}

	// Pad keys to full length (31 bytes for the trie)
	for i := range keys {
		keys[i] = append(keys[i], bytes.Repeat([]byte{0x00}, 32-len(keys[i]))...)
	}

	// Create values with known sizes
	fixedValueSize := 16
	values := make([][]byte, len(keys))
	for i := range values {
		values[i] = fmt.Appendf(nil, "Value-%d-%s", i, strings.Repeat("X", fixedValueSize-8))
	}

	return keys, values
}

func TestTrieStateRangeKeysAndBoundaryNodes(t *testing.T) {
	// Setup test data
	keys, values := setupTestKeys()

	// Setup DB and Trie
	db, err := pebble.NewKVStore()
	require.NoError(t, err)
	defer func() {
		err := db.Close()
		require.NoError(t, err)
	}()

	tr := NewTrie(db)

	// Prepare key-value pairs
	pairs := make([][2][]byte, len(keys))
	for i := range keys {
		pairs[i] = [2][]byte{keys[i], values[i]}
	}

	// Merklize and commit
	root, err := tr.MerklizeAndCommit(pairs)
	require.NoError(t, err)

	// Convert to 31-byte keys
	toKey31 := func(b []byte) [31]byte {
		var key [31]byte
		copy(key[:], b[:31])
		return key
	}

	// Test cases with expected exact key indices
	testCases := []struct {
		name               string
		startKey           []byte
		endKey             []byte
		maxSize            uint32
		expectedKeyIndices []int // Indices into the keys array
		expectedBNodes     int
	}{
		{
			name:               "Full range",
			startKey:           keys[0],
			endKey:             keys[6],
			maxSize:            1000000000,
			expectedKeyIndices: []int{0, 1, 2, 3, 4, 5, 6},
			expectedBNodes:     7,
		},
		{
			name:               "Left branch only",
			startKey:           keys[0],
			endKey:             keys[1],
			maxSize:            1000000000,
			expectedKeyIndices: []int{0, 1},
			expectedBNodes:     4,
		},
		{
			name:               "Right branch only",
			startKey:           keys[2],
			endKey:             keys[6],
			maxSize:            1000000000,
			expectedKeyIndices: []int{2, 3, 4, 5, 6},
			expectedBNodes:     7,
		},
		{
			name:               "Middle subset",
			startKey:           keys[1],
			endKey:             keys[4],
			maxSize:            1000000000,
			expectedKeyIndices: []int{1, 2, 3, 4},
			expectedBNodes:     6,
		},
		{
			name:               "Single key (exact match)",
			startKey:           keys[3],
			endKey:             keys[3],
			maxSize:            1000000000,
			expectedKeyIndices: []int{3},
			expectedBNodes:     4,
		},
		{
			name:               "Deep right branch only",
			startKey:           keys[5],
			endKey:             keys[6],
			maxSize:            1000000000,
			expectedKeyIndices: []int{5, 6},
			expectedBNodes:     6,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := tr.FetchStateTrieRange(root, toKey31(tc.startKey), toKey31(tc.endKey), tc.maxSize)
			require.NoError(t, err)

			// Verify the number of key-value pairs
			require.Equal(t, len(tc.expectedKeyIndices), len(result.Pairs),
				"Expected %d key-value pairs, got %d", len(tc.expectedKeyIndices), len(result.Pairs))

			// Verify the number of boundary nodes
			require.Equal(t, tc.expectedBNodes, len(result.BoundaryNodes),
				"Expected %d boundary nodes, got %d", tc.expectedBNodes, len(result.BoundaryNodes))

			// Verify exact keys and values in order
			for i, expectedIdx := range tc.expectedKeyIndices {
				// Convert pair key to slice for comparison
				keySlice := result.Pairs[i].Key[:]

				// Compare with expected key
				require.Equal(t, keys[expectedIdx][:31], keySlice,
					"Key at position %d doesn't match expected key %d", i, expectedIdx)

				// Compare with expected value
				require.Equal(t, values[expectedIdx], result.Pairs[i].Value,
					"Value at position %d doesn't match expected value %d", i, expectedIdx)
			}

			// Verify keys are in ascending order
			for i := 1; i < len(result.Pairs); i++ {
				prevKeySlice := result.Pairs[i-1].Key[:]
				keySlice := result.Pairs[i].Key[:]
				require.Less(t, bytes.Compare(prevKeySlice, keySlice), 1,
					"Keys are not in ascending order at index %d", i)
			}
		})
	}
}
