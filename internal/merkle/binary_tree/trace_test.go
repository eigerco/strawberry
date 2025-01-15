package binary_tree

import (
	"bytes"
	"github.com/eigerco/strawberry/internal/merkle/binary_tree/testutils"
	"github.com/stretchr/testify/assert"
	"testing"
)

// testTraceCase represents a single test scenario for trace computation
type testTraceCase struct {
	name     string
	blobs    [][]byte
	index    int
	expected [][]byte
}

func TestComputeTrace(t *testing.T) {
	tests := []testTraceCase{
		{
			name:     "empty_blob_list",
			blobs:    [][]byte{},
			index:    0,
			expected: [][]byte{},
		},
		{
			name:     "single_blob",
			blobs:    [][]byte{[]byte("single")},
			index:    0,
			expected: [][]byte{},
		},
		{
			name: "two_blobs_index_0",
			blobs: [][]byte{
				[]byte("blob1"),
				[]byte("blob2"),
			},
			index: 0,
			expected: func() [][]byte {
				h2 := ComputeNode([][]byte{[]byte("blob2")}, testutils.MockHashData)
				return [][]byte{h2}
			}(),
		},
		{
			name: "two_blobs_index_1",
			blobs: [][]byte{
				[]byte("blob1"),
				[]byte("blob2"),
			},
			index: 1,
			expected: func() [][]byte {
				h1 := ComputeNode([][]byte{[]byte("blob1")}, testutils.MockHashData)
				return [][]byte{h1}
			}(),
		},
		{
			name: "three_blobs_index_0",
			blobs: [][]byte{
				[]byte("blob1"),
				[]byte("blob2"),
				[]byte("blob3"),
			},
			index: 0,
			expected: func() [][]byte {
				// For index 0, P⊥ with s=false gives us blob3, and P' with s=true gives us blob2
				// First element should be node from P⊥ (blob3)
				h3 := ComputeNode([][]byte{[]byte("blob3")}, testutils.MockHashData)
				// Second element should be node from blob2
				h2 := ComputeNode([][]byte{[]byte("blob2")}, testutils.MockHashData)
				return [][]byte{h3, h2}
			}(),
		},
		{
			name: "three_blobs_index_1",
			blobs: [][]byte{
				[]byte("blob1"),
				[]byte("blob2"),
				[]byte("blob3"),
			},
			index: 1,
			expected: func() [][]byte {
				h3 := ComputeNode([][]byte{[]byte("blob3")}, testutils.MockHashData)
				h1 := ComputeNode([][]byte{[]byte("blob1")}, testutils.MockHashData)
				return [][]byte{h3, h1}
			}(),
		},
		{
			name: "three_blobs_index_2",
			blobs: [][]byte{
				[]byte("blob1"),
				[]byte("blob2"),
				[]byte("blob3"),
			},
			index: 2,
			expected: func() [][]byte {
				h12 := ComputeNode([][]byte{[]byte("blob1"), []byte("blob2")}, testutils.MockHashData)
				return [][]byte{h12}
			}(),
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
			expected: func() [][]byte {
				h34 := ComputeNode([][]byte{[]byte("blob3"), []byte("blob4")}, testutils.MockHashData)
				h2 := ComputeNode([][]byte{[]byte("blob2")}, testutils.MockHashData)
				return [][]byte{h34, h2}
			}(),
		},
		{
			name: "four_blobs_index_3",
			blobs: [][]byte{
				[]byte("blob1"),
				[]byte("blob2"),
				[]byte("blob3"),
				[]byte("blob4"),
			},
			index: 3,
			expected: func() [][]byte {
				h12 := ComputeNode([][]byte{[]byte("blob1"), []byte("blob2")}, testutils.MockHashData)
				h3 := ComputeNode([][]byte{[]byte("blob3")}, testutils.MockHashData)
				return [][]byte{h12, h3}
			}(),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := ComputeTrace(tc.blobs, tc.index, testutils.MockHashData)
			assert.Equal(t, len(tc.expected), len(result),
				"Trace length mismatch for test %s", tc.name)
			for i := range result {
				if !bytes.Equal(tc.expected[i], result[i]) {
					t.Errorf("Test %s failed at trace element %d:\nexpected: %v\nactual  : %v",
						tc.name, i, tc.expected[i], result[i])
				}
			}
		})
	}
}

func TestComputeTraceProperties(t *testing.T) {
	t.Run("trace_length_property", func(t *testing.T) {
		testCases := []struct {
			numBlobs    int
			expectedLen int
		}{
			{1, 0}, // Single blob has no trace
			{2, 1}, // Need one hash for siblings
			{3, 2}, // Need two hashes: sibling and upper level
			{4, 2}, // Need two hashes: sibling and upper level
			{5, 3}, // Need three hashes
			{6, 3}, // Need three hashes
			{7, 3}, // Need three hashes
			{8, 3}, // Need three hashes
		}

		for _, tc := range testCases {
			blobs := make([][]byte, tc.numBlobs)
			for i := range blobs {
				blobs[i] = []byte{byte(i)}
			}
			trace := ComputeTrace(blobs, 0, testutils.MockHashData)
			assert.Equal(t, tc.expectedLen, len(trace),
				"Incorrect trace length for %d blobs", tc.numBlobs)
		}
	})

	t.Run("trace_verification", func(t *testing.T) {
		blobs := [][]byte{
			[]byte("blob1"),
			[]byte("blob2"),
			[]byte("blob3"),
			[]byte("blob4"),
		}

		for i := range blobs {
			trace := ComputeTrace(blobs, i, testutils.MockHashData)
			// Verify we can reconstruct the root using the trace
			leafHash := ComputeNode([][]byte{blobs[i]}, testutils.MockHashData)
			current := leafHash
			idx := i

			// Process the trace in reverse since we need to build from bottom up
			for i := len(trace) - 1; i >= 0; i-- {
				var combined []byte
				if idx%2 == 0 {
					combined = append([]byte("node"), append(current, trace[i]...)...)
				} else {
					combined = append([]byte("node"), append(trace[i], current...)...)
				}
				current = convertHashToBlob(testutils.MockHashData(combined))
				idx /= 2
			}

			// Compute expected root
			expectedRoot := ComputeNode(blobs, testutils.MockHashData)
			assert.Equal(t, expectedRoot, current,
				"Root reconstruction failed for index %d", i)
		}
	})
}
