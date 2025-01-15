package binary_tree

import (
	"github.com/eigerco/strawberry/internal/crypto"
)

// ComputeNode Computes the Merkle node for a given sequence of blobs.
func ComputeNode(blobs [][]byte, hashFunc func([]byte) crypto.Hash) []byte {
	if len(blobs) == 0 {
		return []byte{}
	}

	// If |blobs| = 1, return the hash of blobs[0]
	if len(blobs) == 1 {
		return convertHashToBlob(hashFunc(blobs[0]))
	}

	// Otherwise, compute the recursive hash combination
	mid := len(blobs) / 2
	left := ComputeNode(blobs[:mid], hashFunc)
	right := ComputeNode(blobs[mid:], hashFunc)

	// Concatenate "node", left, and right
	combined := append([]byte("node"), append(left, right...)...)

	return convertHashToBlob(hashFunc(combined))
}
