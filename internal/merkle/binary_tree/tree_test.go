package binary_tree

import (
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/merkle/binary_tree/testutils"
	"github.com/stretchr/testify/assert"
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
				left := testutils.MockHashData([]byte("blob1"))
				right := testutils.MockHashData([]byte("blob2"))
				combined := append([]byte("$node"), append(convertHashToBlob(left), convertHashToBlob(right)...)...)
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
				// Should expect just one $node prefix
				return testutils.MockHashData(append([]byte("$node"), []byte("blob1")...))
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
				leafHash := testutils.MockHashData(append([]byte("$leaf"), []byte("blob1")...))
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
				h1 := testutils.MockHashData(append([]byte("$leaf"), []byte("blob1")...))
				h2 := testutils.MockHashData(append([]byte("$leaf"), []byte("blob2")...))
				combined := append([]byte("$node"), append(convertHashToBlob(h1), convertHashToBlob(h2)...)...)
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
				h1 := testutils.MockHashData(append([]byte("$leaf"), []byte("blob1")...))
				h2 := testutils.MockHashData(append([]byte("$leaf"), []byte("blob2")...))
				h12 := testutils.MockHashData(append([]byte("$node"), append(convertHashToBlob(h1), convertHashToBlob(h2)...)...))
				h3 := testutils.MockHashData(append([]byte("$leaf"), []byte("blob3")...))
				h4 := crypto.Hash{} // Zero hash for padding
				h34 := testutils.MockHashData(append([]byte("$node"), append(convertHashToBlob(h3), convertHashToBlob(h4)...)...))
				combined := append([]byte("$node"), append(convertHashToBlob(h12), convertHashToBlob(h34)...)...)
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

func TestGenerateJustification(t *testing.T) {
	tests := []struct {
		name     string
		blobs    [][]byte
		index    int
		expected []crypto.Hash
	}{
		{
			name:     "empty_blob_list",
			blobs:    [][]byte{},
			index:    0,
			expected: []crypto.Hash{},
		},
		{
			name:     "single_blob",
			blobs:    [][]byte{[]byte("blob1")},
			index:    0,
			expected: []crypto.Hash{},
		},
		{
			name: "four_blobs_index_0",
			blobs: [][]byte{
				[]byte("blob1"),
				[]byte("blob2"),
				[]byte("blob3"),
				[]byte("blob4"),
			},
			index: 0,
			expected: func() []crypto.Hash {
				h3 := testutils.MockHashData(append([]byte("$leaf"), []byte("blob3")...))
				h4 := testutils.MockHashData(append([]byte("$leaf"), []byte("blob4")...))
				h34 := testutils.MockHashData(append([]byte("$node"), append(convertHashToBlob(h3), convertHashToBlob(h4)...)...))
				h2 := testutils.MockHashData(append([]byte("$leaf"), []byte("blob2")...))
				return []crypto.Hash{h34, h2}
			}(),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := GenerateJustification(tc.blobs, tc.index, testutils.MockHashData)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestGenerateLimitedJustification(t *testing.T) {
	tests := []struct {
		name     string
		blobs    [][]byte
		index    int
		expected []crypto.Hash
	}{
		{
			name:     "empty_blob_list",
			blobs:    [][]byte{},
			index:    0,
			expected: []crypto.Hash{},
		},
		{
			name: "eight_blobs_limited",
			blobs: [][]byte{
				[]byte("1"), []byte("2"), []byte("3"), []byte("4"),
				[]byte("5"), []byte("6"), []byte("7"), []byte("8"),
			},
			index: 0,
			expected: func() []crypto.Hash {
				// log2(8) = 3, so we get max 3 hashes
				h2 := testutils.MockHashData(append([]byte("$leaf"), []byte("2")...))
				h34 := testutils.MockHashData(append([]byte("$node"),
					append(
						convertHashToBlob(testutils.MockHashData(append([]byte("$leaf"), []byte("3")...))),
						convertHashToBlob(testutils.MockHashData(append([]byte("$leaf"), []byte("4")...)))...,
					)...,
				))
				h5678 := testutils.MockHashData(append([]byte("$node"),
					append(
						convertHashToBlob(testutils.MockHashData(append([]byte("$node"),
							append(
								convertHashToBlob(testutils.MockHashData(append([]byte("$leaf"), []byte("5")...))),
								convertHashToBlob(testutils.MockHashData(append([]byte("$leaf"), []byte("6")...)))...,
							)...,
						))),
						convertHashToBlob(testutils.MockHashData(append([]byte("$node"),
							append(
								convertHashToBlob(testutils.MockHashData(append([]byte("$leaf"), []byte("7")...))),
								convertHashToBlob(testutils.MockHashData(append([]byte("$leaf"), []byte("8")...)))...,
							)...,
						)))...,
					)...,
				))
				// We expect the last 3 hashes, order from higher level to lower level
				return []crypto.Hash{h5678, h34, h2}
			}(),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := GenerateLimitedJustification(tc.blobs, tc.index, testutils.MockHashData)
			assert.Equal(t, tc.expected, result)
		})
	}
}

// Property tests
func TestTreeProperties(t *testing.T) {
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

	t.Run("justification_verification", func(t *testing.T) {
		blobs := [][]byte{
			[]byte("blob1"),
			[]byte("blob2"),
			[]byte("blob3"),
			[]byte("blob4"),
		}

		for i := range blobs {
			proof := GenerateJustification(blobs, i, testutils.MockHashData)

			// Verify proof leads to same root
			expected := ComputeConstantDepthRoot(blobs, testutils.MockHashData)

			// Compute leaf hash
			leafHash := testutils.MockHashData(append([]byte("$leaf"), blobs[i]...))
			current := convertHashToBlob(leafHash)
			idx := i

			// Reconstruct root
			for i := len(proof) - 1; i >= 0; i-- {
				var combined []byte
				if idx%2 == 0 {
					combined = append([]byte("$node"), append(current, convertHashToBlob(proof[i])...)...)
				} else {
					combined = append([]byte("$node"), append(convertHashToBlob(proof[i]), current...)...)
				}
				current = convertHashToBlob(testutils.MockHashData(combined))[:]
				idx /= 2
			}

			assert.Equal(t, expected[:], current,
				"Proof verification failed for index %d", i)
		}
	})
}
