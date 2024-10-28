package binary_tree

import (
	"github.com/eigerco/strawberry/internal/crypto"
	"math"
)

// ComputeWellBalancedRoot computes the root hash of a well-balanced Binary Merkle tree.
// Suitable for data not much greater than 32 octets in length as it avoids
// hashing each item in the sequence.
func ComputeWellBalancedRoot(blobs [][]byte, hashFunc func([]byte) crypto.Hash) crypto.Hash {
	if len(blobs) == 0 {
		return crypto.Hash{}
	}

	// If |v| = 1, return H(v0)
	if len(blobs) == 1 {
		return hashFunc(blobs[0])
	}

	// Otherwise return N(v, H)
	return crypto.Hash(ComputeNode(blobs, hashFunc))
}

// ComputeConstantDepthRoot computes the root hash of a constant-depth Binary Merkle tree.
// Preprocesses data with leaf prefix and pads to power of 2 size, making it
// suitable for larger data items and constant-size proofs.
func ComputeConstantDepthRoot(blobs [][]byte, hashFunc func([]byte) crypto.Hash) crypto.Hash {
	if len(blobs) == 0 {
		return crypto.Hash{} // return zero hash for empty input
	}
	// M(v, H) = N(C(v, H), H)
	preprocessed := preprocessForConstantDepth(blobs, hashFunc)
	return crypto.Hash(ComputeNode(preprocessed, hashFunc))
}

// GenerateJustification implements the justification generation function from equation (324)
func GenerateJustification(blobs [][]byte, index int, hashFunc func([]byte) crypto.Hash) []crypto.Hash {
	// J(v, i, H) = T(C(v, H), i, H)
	preprocessed := preprocessForConstantDepth(blobs, hashFunc)
	return convertBlobsToHashes(ComputeTrace(preprocessed, index, hashFunc))
}

// GenerateLimitedJustification implements the limited justification generation function from equation (325)
func GenerateLimitedJustification(blobs [][]byte, index int, hashFunc func([]byte) crypto.Hash) []crypto.Hash {
	preprocessed := preprocessForConstantDepth(blobs, hashFunc)
	trace := ComputeTrace(preprocessed, index, hashFunc)

	// Limit trace to max(0, ⌊log₂(max(1,|v|))⌋-x)
	maxLen := int(math.Floor(math.Log2(math.Max(1, float64(len(blobs))))))
	if maxLen == 0 {
		return []crypto.Hash{}
	}

	if len(trace) > maxLen {
		trace = trace[:maxLen]
	}
	return convertBlobsToHashes(trace)
}

// preprocessForConstantDepth implements the preprocessing function C from equation (326)
func preprocessForConstantDepth(blobs [][]byte, hashFunc func([]byte) crypto.Hash) [][]byte {
	if len(blobs) == 0 {
		return [][]byte{}
	}

	// Calculate target length: |v'| = 2^⌈log₂(max(1,|v|))⌉
	targetLen := 1 << uint(math.Ceil(math.Log2(math.Max(1, float64(len(blobs))))))

	// Create result slice with target length.
	result := make([][]byte, targetLen)

	// Process each input: H($leaf ~ vi) for i < |v|
	for i := 0; i < len(blobs); i++ {
		combined := append([]byte("$leaf"), blobs[i]...)
		result[i] = convertHashToBlob(hashFunc(combined))
	} // positions ≥ len(blobs) are already zero hashes, so no action needed

	return result
}
