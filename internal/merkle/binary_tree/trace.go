package binary_tree

import (
	"github.com/eigerco/strawberry/internal/crypto"
)

func ComputeTrace(blobs [][]byte, index int, hashFunc func([]byte) crypto.Hash) [][]byte {
	if len(blobs) <= 1 {
		return [][]byte{}
	}

	// Compute current node - N(P⊥(v,i),H)
	node := ComputeNode(computeP(blobs, index, false), hashFunc)

	// Get recursive trace - T(P⊤(v,i), i-PI(v,i), H)
	trace := ComputeTrace(computeP(blobs, index, true), index-computePi(blobs, index), hashFunc)

	return append([][]byte{node}, trace...)
}

func computeP(blobs [][]byte, index int, s bool) [][]byte {
	mid := getMid(blobs)
	if index < mid == s {
		return blobs[:mid]
	}
	return blobs[mid:]
}

func computePi(blobs [][]byte, index int) int {
	mid := getMid(blobs)
	if index < mid {
		return 0
	}
	return mid
}

func getMid(blobs [][]byte) int {
	return len(blobs) - len(blobs)/2 // Round up for odd lengths
}
