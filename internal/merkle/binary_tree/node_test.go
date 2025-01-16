package binary_tree

import (
	"bytes"
	"github.com/eigerco/strawberry/internal/merkle/binary_tree/testutils"
	"github.com/stretchr/testify/assert"
	"testing"
)

// testNodeCase represents a single test scenario for node computation
type testNodeCase struct {
	name     string
	blobs    [][]byte
	expected []byte
}

// Helper function to create a blob of specific size
func createBlob(size int) []byte {
	blob := make([]byte, size)
	for i := range blob {
		blob[i] = byte(i % 256)
	}
	return blob
}

func TestComputeNode(t *testing.T) {
	tests := []testNodeCase{
		{
			name:     "empty_blob_list",
			blobs:    [][]byte{},
			expected: []byte{},
		},
		{
			name:     "single_empty_blob",
			blobs:    [][]byte{{}},
			expected: convertHashToBlob(testutils.MockHashData([]byte{})),
		},
		{
			name:     "single_blob",
			blobs:    [][]byte{[]byte("single blob")},
			expected: convertHashToBlob(testutils.MockHashData([]byte("single blob"))),
		},
		{
			name: "two_blobs",
			blobs: [][]byte{
				[]byte("blob1"),
				[]byte("blob2"),
			},
			expected: func() []byte {
				hash1 := convertHashToBlob(testutils.MockHashData([]byte("blob1")))
				hash2 := convertHashToBlob(testutils.MockHashData([]byte("blob2")))
				combined := append([]byte("node"), append(hash1, hash2...)...)
				return convertHashToBlob(testutils.MockHashData(combined))
			}(),
		},
		{
			name: "three_blobs",
			blobs: [][]byte{
				[]byte("blob1"),
				[]byte("blob2"),
				[]byte("blob3"),
			},
			expected: func() []byte {
				// Right side (blob2 and blob3)
				hash2 := convertHashToBlob(testutils.MockHashData([]byte("blob2")))
				hash3 := convertHashToBlob(testutils.MockHashData([]byte("blob3")))
				rightNode := append([]byte("node"), append(hash2, hash3...)...)
				rightHash := convertHashToBlob(testutils.MockHashData(rightNode))

				// Left side (blob1)
				leftHash := convertHashToBlob(testutils.MockHashData([]byte("blob1")))

				// Combine
				combined := append([]byte("node"), append(leftHash, rightHash...)...)
				return convertHashToBlob(testutils.MockHashData(combined))
			}(),
		},
		{
			name: "four_blobs",
			blobs: [][]byte{
				[]byte("blob1"),
				[]byte("blob2"),
				[]byte("blob3"),
				[]byte("blob4"),
			},
			expected: func() []byte {
				// Left subtree
				hash1 := convertHashToBlob(testutils.MockHashData([]byte("blob1")))
				hash2 := convertHashToBlob(testutils.MockHashData([]byte("blob2")))
				leftNode := append([]byte("node"), append(hash1, hash2...)...)
				leftHash := convertHashToBlob(testutils.MockHashData(leftNode))

				// Right subtree
				hash3 := convertHashToBlob(testutils.MockHashData([]byte("blob3")))
				hash4 := convertHashToBlob(testutils.MockHashData([]byte("blob4")))
				rightNode := append([]byte("node"), append(hash3, hash4...)...)
				rightHash := convertHashToBlob(testutils.MockHashData(rightNode))

				combined := append([]byte("node"), append(leftHash, rightHash...)...)
				return convertHashToBlob(testutils.MockHashData(combined))
			}(),
		},
		{
			name: "all_empty_blobs",
			blobs: [][]byte{
				{},
				{},
				{},
			},
			expected: func() []byte {
				emptyHash := convertHashToBlob(testutils.MockHashData([]byte{}))
				rightNode := append([]byte("node"), append(emptyHash, emptyHash...)...)
				rightHash := convertHashToBlob(testutils.MockHashData(rightNode))
				leftHash := convertHashToBlob(testutils.MockHashData([]byte{}))
				combined := append([]byte("node"), append(leftHash, rightHash...)...)
				return convertHashToBlob(testutils.MockHashData(combined))
			}(),
		},
		{
			name: "large_blobs",
			blobs: [][]byte{
				createBlob(1024),
				createBlob(2048),
			},
			expected: func() []byte {
				hash1 := convertHashToBlob(testutils.MockHashData(createBlob(1024)))
				hash2 := convertHashToBlob(testutils.MockHashData(createBlob(2048)))
				combined := append([]byte("node"), append(hash1, hash2...)...)
				return convertHashToBlob(testutils.MockHashData(combined))
			}(),
		},
		{
			name: "mixed_size_blobs",
			blobs: [][]byte{
				[]byte("small"),
				createBlob(1024),
				[]byte(""),
			},
			expected: func() []byte {
				// Right side (large blob and empty blob)
				hash2 := convertHashToBlob(testutils.MockHashData(createBlob(1024)))
				hash3 := convertHashToBlob(testutils.MockHashData([]byte("")))
				rightNode := append([]byte("node"), append(hash2, hash3...)...)
				rightHash := convertHashToBlob(testutils.MockHashData(rightNode))

				// Left side (small blob)
				leftHash := convertHashToBlob(testutils.MockHashData([]byte("small")))

				combined := append([]byte("node"), append(leftHash, rightHash...)...)
				return convertHashToBlob(testutils.MockHashData(combined))
			}(),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := ComputeNode(tc.blobs, testutils.MockHashData)
			if !bytes.Equal(tc.expected, result) {
				t.Errorf("Test %s failed:\nexpected: %v\nactual  : %v",
					tc.name, tc.expected, result)
			}
		})
	}
}

// TestComputeNodeProperties tests invariant properties that should hold true
// for any valid implementation of ComputeNode
func TestComputeNodeProperties(t *testing.T) {
	t.Run("deterministic_output", func(t *testing.T) {
		blobs := [][]byte{[]byte("test1"), []byte("test2")}
		result1 := ComputeNode(blobs, testutils.MockHashData)
		result2 := ComputeNode(blobs, testutils.MockHashData)
		assert.Equal(t, result1, result2, "ComputeNode should be deterministic")
	})

	t.Run("order_matters", func(t *testing.T) {
		blobs1 := [][]byte{[]byte("test1"), []byte("test2")}
		blobs2 := [][]byte{[]byte("test2"), []byte("test1")}
		result1 := ComputeNode(blobs1, testutils.MockHashData)
		result2 := ComputeNode(blobs2, testutils.MockHashData)
		assert.NotEqual(t, result1, result2, "Order of blobs should affect the result")
	})

	t.Run("deep_tree", func(t *testing.T) {
		// Create a deep tree with 8 blobs
		blobs := make([][]byte, 8)
		for i := range blobs {
			blobs[i] = []byte{byte(i)}
		}
		// Should not stack overflow
		result := ComputeNode(blobs, testutils.MockHashData)
		assert.NotNil(t, result, "Should handle deep trees without stack overflow")
	})
}
