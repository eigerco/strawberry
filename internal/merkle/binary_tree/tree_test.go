package binary_tree

import (
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/merkle/binary_tree/testutils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"math/bits"
	"testing"
)

func TestComputeWellBalancedRoot(t *testing.T) {
	tests := []struct {
		name     string
		blobs    [][]byte
		expected crypto.Hash
	}{
		{
			name:     "empty_blob_list",
			blobs:    [][]byte{},
			expected: crypto.Hash{},
		},
		{
			name:     "single_blob",
			blobs:    [][]byte{[]byte("single")},
			expected: testutils.MockHashData([]byte("single")),
		},
		{
			name: "two_blobs",
			blobs: [][]byte{
				[]byte("blob1"),
				[]byte("blob2"),
			},
			expected: func() crypto.Hash {
				left := []byte("blob1")
				right := []byte("blob2")
				combined := append([]byte("node"), append(left, right...)...)
				return testutils.MockHashData(combined)
			}(),
		},
		{
			name: "three_blobs",
			blobs: [][]byte{
				[]byte("blob1"),
				[]byte("blob2"),
				[]byte("blob3"),
			},
			expected: func() crypto.Hash {
				leaf1 := []byte("blob1")
				leaf2 := []byte("blob2")
				left := testutils.MockHashData(append([]byte("node"), append(leaf1, leaf2...)...))

				// Right subtree: [blob3] - single element, not hashed in N function
				right := []byte("blob3")

				// Combine with node prefix
				return testutils.MockHashData(append([]byte("node"), append(left[:], right...)...))
			}(),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := ComputeWellBalancedRoot(tc.blobs, testutils.MockHashData)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestComputeConstantDepthRoot(t *testing.T) {
	tests := []struct {
		name     string
		blobs    [][]byte
		expected crypto.Hash
	}{
		{
			name:     "empty_blob_list",
			blobs:    [][]byte{},
			expected: crypto.Hash{},
		},
		{
			name:  "single_blob",
			blobs: [][]byte{[]byte("blob1")},
			expected: func() crypto.Hash {
				leafHash := testutils.MockHashData(append([]byte("leaf"), []byte("blob1")...))
				return leafHash
			}(),
		},
		{
			name: "two_blobs",
			blobs: [][]byte{
				[]byte("blob1"),
				[]byte("blob2"),
			},
			expected: func() crypto.Hash {
				h1 := testutils.MockHashData(append([]byte("leaf"), []byte("blob1")...))
				h2 := testutils.MockHashData(append([]byte("leaf"), []byte("blob2")...))
				combined := append([]byte("node"), append(convertHashToBlob(h1), convertHashToBlob(h2)...)...)
				return testutils.MockHashData(combined)
			}(),
		},
		{
			name: "three_blobs_padded_to_four",
			blobs: [][]byte{
				[]byte("blob1"),
				[]byte("blob2"),
				[]byte("blob3"),
			},
			expected: func() crypto.Hash {
				h1 := testutils.MockHashData(append([]byte("leaf"), []byte("blob1")...))
				h2 := testutils.MockHashData(append([]byte("leaf"), []byte("blob2")...))
				h12 := testutils.MockHashData(append([]byte("node"), append(convertHashToBlob(h1), convertHashToBlob(h2)...)...))
				h3 := testutils.MockHashData(append([]byte("leaf"), []byte("blob3")...))
				h4 := crypto.Hash{} // Zero hash for padding
				h34 := testutils.MockHashData(append([]byte("node"), append(convertHashToBlob(h3), convertHashToBlob(h4)...)...))
				combined := append([]byte("node"), append(convertHashToBlob(h12), convertHashToBlob(h34)...)...)
				return testutils.MockHashData(combined)
			}(),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := ComputeConstantDepthRoot(tc.blobs, testutils.MockHashData)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestGetLeafPage(t *testing.T) {
	tests := []struct {
		name     string
		v        [][]byte
		i        int
		x        int
		expected []crypto.Hash
	}{
		{
			name:     "x_too_large",
			v:        [][]byte{[]byte("1")},
			i:        0,
			x:        bits.UintSize,
			expected: []crypto.Hash{},
		},
		{
			name:     "empty_vector",
			v:        [][]byte{},
			i:        0,
			x:        0,
			expected: []crypto.Hash{},
		},
		{
			name: "single_blob_x0",
			v:    [][]byte{[]byte("1")},
			i:    0,
			x:    0,
			expected: []crypto.Hash{
				testutils.MockHashData(append([]byte("leaf"), []byte("1")...)),
			},
		},
		{
			name: "four_blobs_first_page_x1",
			v: [][]byte{
				[]byte("1"), []byte("2"), []byte("3"), []byte("4"),
			},
			i: 0,
			x: 1,
			expected: []crypto.Hash{
				testutils.MockHashData(append([]byte("leaf"), []byte("1")...)),
				testutils.MockHashData(append([]byte("leaf"), []byte("2")...)),
			},
		},
		{
			name: "four_blobs_second_page_x1",
			v: [][]byte{
				[]byte("1"), []byte("2"), []byte("3"), []byte("4"),
			},
			i: 1,
			x: 1,
			expected: []crypto.Hash{
				testutils.MockHashData(append([]byte("leaf"), []byte("3")...)),
				testutils.MockHashData(append([]byte("leaf"), []byte("4")...)),
			},
		},
		{
			name: "five_blobs_third_page_x1_partial",
			v: [][]byte{
				[]byte("1"), []byte("2"), []byte("3"), []byte("4"), []byte("5"),
			},
			i: 2,
			x: 1,
			expected: []crypto.Hash{
				testutils.MockHashData(append([]byte("leaf"), []byte("5")...)),
			},
		},
		{
			name: "eight_blobs_x2",
			v: [][]byte{
				[]byte("1"), []byte("2"), []byte("3"), []byte("4"),
				[]byte("5"), []byte("6"), []byte("7"), []byte("8"),
			},
			i: 0,
			x: 2,
			expected: []crypto.Hash{
				testutils.MockHashData(append([]byte("leaf"), []byte("1")...)),
				testutils.MockHashData(append([]byte("leaf"), []byte("2")...)),
				testutils.MockHashData(append([]byte("leaf"), []byte("3")...)),
				testutils.MockHashData(append([]byte("leaf"), []byte("4")...)),
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := GetLeafPage(tc.v, tc.i, tc.x, testutils.MockHashData)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestGeneratePageProof(t *testing.T) {
	tests := []struct {
		name     string
		v        [][]byte
		i        int
		x        int
		expected []crypto.Hash
	}{
		{
			name:     "empty_vector",
			v:        [][]byte{},
			i:        0,
			x:        0,
			expected: []crypto.Hash{},
		},
		{
			name:     "single_blob",
			v:        [][]byte{[]byte("1")},
			i:        0,
			x:        0,
			expected: []crypto.Hash{},
		},
		{
			name: "four_blobs_first_page_x1",
			v: [][]byte{
				[]byte("1"), []byte("2"), []byte("3"), []byte("4"),
			},
			i: 0,
			x: 1,
			expected: func() []crypto.Hash {
				h34 := testutils.MockHashData(append([]byte("node"),
					append(
						convertHashToBlob(testutils.MockHashData(append([]byte("leaf"), []byte("3")...))),
						convertHashToBlob(testutils.MockHashData(append([]byte("leaf"), []byte("4")...)))...,
					)...,
				))
				return []crypto.Hash{h34}
			}(),
		},
		{
			name: "eight_blobs_first_page_x2",
			v: [][]byte{
				[]byte("1"), []byte("2"), []byte("3"), []byte("4"),
				[]byte("5"), []byte("6"), []byte("7"), []byte("8"),
			},
			i: 0,
			x: 2,
			expected: func() []crypto.Hash {
				h5678 := testutils.MockHashData(append([]byte("node"),
					append(
						convertHashToBlob(testutils.MockHashData(append([]byte("node"),
							append(
								convertHashToBlob(testutils.MockHashData(append([]byte("leaf"), []byte("5")...))),
								convertHashToBlob(testutils.MockHashData(append([]byte("leaf"), []byte("6")...)))...,
							)...,
						))),
						convertHashToBlob(testutils.MockHashData(append([]byte("node"),
							append(
								convertHashToBlob(testutils.MockHashData(append([]byte("leaf"), []byte("7")...))),
								convertHashToBlob(testutils.MockHashData(append([]byte("leaf"), []byte("8")...)))...,
							)...,
						)))...,
					)...,
				))
				return []crypto.Hash{h5678}
			}(),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := GeneratePageProof(tc.v, tc.i, tc.x, testutils.MockHashData)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestPageProofReconstruction(t *testing.T) {
	// Test data
	blobs := [][]byte{
		[]byte("blob1"),
		[]byte("blob2"),
		[]byte("blob3"),
		[]byte("blob4"),
	}

	// Test different page sizes (x values)
	testCases := []struct {
		name      string
		x         int // Page size exponent
		pageIndex int
	}{
		{"single_item_page", 0, 0}, // 2^0 = 1 item per page
		{"two_item_page", 1, 0},    // 2^1 = 2 items per page
		{"four_item_page", 2, 0},   // 2^2 = 4 items per page
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Generate proof for the specified page
			proof := GeneratePageProof(blobs, tc.pageIndex, tc.x, testutils.MockHashData)

			// Get the leaf page
			leafPage := GetLeafPage(blobs, tc.pageIndex, tc.x, testutils.MockHashData)

			// Verify proof leads to same root
			expected := ComputeConstantDepthRoot(blobs, testutils.MockHashData)

			// Start with the leaf page hashes combined in a balanced way
			current := make([]byte, 0)
			leafLen := len(leafPage)

			// Build a balanced tree from the leaf page
			level := leafPage
			for len(level) > 1 {
				nextLevel := make([]crypto.Hash, (len(level)+1)/2)
				for i := 0; i < len(level); i += 2 {
					if i+1 < len(level) {
						nodeInput := append([]byte("node"),
							append(convertHashToBlob(level[i]),
								convertHashToBlob(level[i+1])...)...)
						nextLevel[i/2] = testutils.MockHashData(nodeInput)
					} else {
						// Odd number of nodes, promote the last one
						nextLevel[i/2] = level[i]
					}
				}
				level = nextLevel
			}

			if leafLen > 0 {
				current = convertHashToBlob(level[0])
			}

			// Apply proof elements
			idx := tc.pageIndex
			for i := len(proof) - 1; i >= 0; i-- {
				var combined []byte
				if idx%2 == 0 {
					combined = append([]byte("node"), append(current, convertHashToBlob(proof[i])...)...)
				} else {
					combined = append([]byte("node"), append(convertHashToBlob(proof[i]), current...)...)
				}
				current = convertHashToBlob(testutils.MockHashData(combined))
				idx /= 2
			}

			// Final verification
			require.Equal(t, expected[:], current,
				"Proof verification failed for page size 2^%d at index %d",
				tc.x, tc.pageIndex)
		})
	}

	// Test error cases
	t.Run("empty_blobs", func(t *testing.T) {
		proof := GeneratePageProof([][]byte{}, 0, 0, testutils.MockHashData)
		require.Empty(t, proof, "Proof for empty blobs should be empty")
	})

	t.Run("out_of_bounds_page", func(t *testing.T) {
		proof := GeneratePageProof(blobs, 5, 0, testutils.MockHashData)
		require.NotNil(t, proof, "Should handle out of bounds page index")
	})
}

// Property tests
func TestPreprocessForConstantDepth(t *testing.T) {
	t.Run("constant_depth_padding", func(t *testing.T) {
		testCases := []struct {
			numBlobs    int
			expectedLen int
		}{
			{1, 1},  // 2^0
			{2, 2},  // 2^1
			{3, 4},  // 2^2
			{4, 4},  // 2^2
			{5, 8},  // 2^3
			{7, 8},  // 2^3
			{8, 8},  // 2^3
			{9, 16}, // 2^4
		}

		for _, tc := range testCases {
			blobs := make([][]byte, tc.numBlobs)
			for i := range blobs {
				blobs[i] = []byte{byte(i)}
			}
			preprocessed := preprocessForConstantDepth(blobs, testutils.MockHashData)
			assert.Equal(t, tc.expectedLen, len(preprocessed),
				"Incorrect padded length for %d blobs", tc.numBlobs)
		}
	})
}
