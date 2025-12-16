package binary_tree

import (
	"math/bits"

	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/safemath"
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

// GeneratePageProof implements Jx (equation E.5, Graypaper v0.7.2):
//
//	Jx: {⟦B⟧, N|v|, B → H} → ⟦H⟧
//	(v, i, H) ↦ T(C(v, H), 2^x·i, H)[... max(0, ⌈log₂(max(1,|v|))⌉ - x)]
//
// Parameters map to spec as: blobs=v, pageIndex=i, hashFunc=H, x=x
func GeneratePageProof(blobs [][]byte, pageIndex, x int, hashFunc func([]byte) crypto.Hash) []crypto.Hash {
	// Guard: empty v produces empty result
	// Guard: x must be valid for shift operations
	// Guard: i (pageIndex) must be non-negative per N|v| domain
	if len(blobs) == 0 || x < 0 || x >= bits.UintSize-1 || pageIndex < 0 {
		return []crypto.Hash{}
	}

	// 2^x
	pageSize := 1 << x

	// 2^x · i
	traceIndex, ok := safemath.Mul(pageSize, pageIndex)
	if !ok {
		return []crypto.Hash{}
	}

	// C(v, H)
	preprocessed := preprocessForConstantDepth(blobs, hashFunc)

	// T(C(v, H), 2^x·i, H)
	fullTrace := ComputeTrace(preprocessed, traceIndex, hashFunc)

	// ⌈log₂(max(1,|v|))⌉ using integer arithmetic
	// For n >= 1: ⌈log₂(n)⌉ = bits.Len(n - 1)
	logLen := bits.Len(uint(len(blobs) - 1))

	// max(0, ⌈log₂(max(1,|v|))⌉ - x)
	maxLen := max(0, logLen-x)

	if maxLen == 0 {
		return []crypto.Hash{}
	}

	// T(...)[... max(0, ⌈log₂(max(1,|v|))⌉ - x)]
	// Clamp to actual trace length to prevent slice bounds panic
	maxLen = min(maxLen, len(fullTrace))

	return convertBlobsToHashes(fullTrace[:maxLen])
}

// GetLeafPage implements Lx (equation E.6 v0.7.2):
//
//	Lx: {⟦B⟧, N|v|, B → H} → ⟦H⟧
//	(v, i, H) ↦ [H($leaf ⌢ l) | l ←< v[2^x·i ... min(2^x·i + 2^x, |v|)]]
//
// Parameters map to spec as: blobs=v, pageIndex=i, x=x, hashFunc=H
func GetLeafPage(blobs [][]byte, pageIndex, x int, hashFunc func([]byte) crypto.Hash) []crypto.Hash {
	// Guard: empty v produces empty result
	// Guard: x must be valid for shift operations
	// Guard: i (pageIndex) must be non-negative per N|v| domain
	if len(blobs) == 0 || x < 0 || x >= bits.UintSize-1 || pageIndex < 0 {
		return []crypto.Hash{}
	}

	// 2^x
	pageSize := 1 << x

	// 2^x · i
	pageStart, ok := safemath.Mul(pageSize, pageIndex)
	if !ok || pageStart >= len(blobs) {
		return []crypto.Hash{}
	}

	// min(2^x·i + 2^x, |v|)
	// Overflow in addition means page extends beyond data; clamp to |v|
	pageEnd, ok := safemath.Add(pageStart, pageSize)
	if !ok || pageEnd > len(blobs) {
		pageEnd = len(blobs)
	}

	// [H($leaf ⌢ l) | l ←< v[2^x·i ... min(2^x·i + 2^x, |v|)]]
	leaveHashes := make([]crypto.Hash, 0, pageEnd-pageStart)
	for j := pageStart; j < pageEnd; j++ {
		// H($leaf ⌢ l) where $leaf = "leaf" prefix
		prefixedLeaf := append([]byte("leaf"), blobs[j]...)
		leaveHashes = append(leaveHashes, hashFunc(prefixedLeaf))
	}
	return leaveHashes
}

// preprocessForConstantDepth implements the preprocessing function C from equation (E7) v0.7.2
func preprocessForConstantDepth(blobs [][]byte, hashFunc func([]byte) crypto.Hash) [][]byte {
	if len(blobs) == 0 {
		return [][]byte{}
	}

	// Calculate target length: |v'| = 2^⌈log₂(max(1,|v|))⌉
	targetLen := 1
	if len(blobs) > 1 {
		targetLen = 1 << bits.Len(uint(len(blobs)-1))
	}

	result := make([][]byte, targetLen)

	// H($leaf ⌢ vᵢ) for i < |v|
	prefix := []byte("leaf")
	for i, blob := range blobs {
		combined := make([]byte, len(prefix)+len(blob))
		copy(combined, prefix)
		copy(combined[len(prefix):], blob)
		result[i] = convertHashToBlob(hashFunc(combined))
	}

	// H₀ for positions ≥ |v|
	zeroHash := convertHashToBlob(crypto.Hash{})
	for i := len(blobs); i < targetLen; i++ {
		result[i] = zeroHash
	}

	return result
}
