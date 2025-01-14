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
// suitable for larger data items and constant-size proofs. Graypaper 0.5.4
func ComputeConstantDepthRoot(blobs [][]byte, hashFunc func([]byte) crypto.Hash) crypto.Hash {
	if len(blobs) == 0 {
		return crypto.Hash{} // return zero hash for empty input
	}
	// M(v, H) = N(C(v, H), H)
	preprocessed := preprocessForConstantDepth(blobs, hashFunc)
	return crypto.Hash(ComputeNode(preprocessed, hashFunc))
}

// GeneratePageProof implements Jx (Merkle path to a single page). Graypaper 0.5.4
func GeneratePageProof(v [][]byte, i, x int, H func([]byte) crypto.Hash) []crypto.Hash {
	if len(v) == 0 {
		return []crypto.Hash{}
	}

	// T(C(v,H), 2^x*i, H)...max(0,⌊log₂(max(1,|v|))⌋-x)
	preprocessed := preprocessForConstantDepth(v, H)
	fullTrace := ComputeTrace(preprocessed, (1<<x)*i, H)

	// Apply length limiting to trace
	maxLen := max(0, int(math.Floor(math.Log2(math.Max(1, float64(len(v))))))-x)
	if maxLen == 0 {
		return []crypto.Hash{}
	}

	return convertBlobsToHashes(fullTrace[:maxLen])
}

// GetLeafPage implements Lx (retrieves a single page of hashed leaves). Graypaper 0.5.4
func GetLeafPage(blobs [][]byte, pageIndex, x int, hashFunc func([]byte) crypto.Hash) []crypto.Hash {
	if len(blobs) == 0 {
		return []crypto.Hash{}
	}

	// Calculate range bounds for leaf page
	pageStart := (1 << x) * pageIndex          // 2^x * i
	pageEnd := min(pageStart+1<<x, len(blobs)) // min(2^x * i + 2^x, |v|)

	// Select and hash leaves from the range with "$leaf" prefix
	leaveHashes := make([]crypto.Hash, 0, pageEnd-pageStart)
	for j := pageStart; j < pageEnd; j++ {
		prefixedLeaf := append([]byte("$leaf"), blobs[j]...)
		leaveHashes = append(leaveHashes, hashFunc(prefixedLeaf))
	}

	return leaveHashes
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
