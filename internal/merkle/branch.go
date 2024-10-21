package merkle

import "github.com/eigerco/strawberry/internal/crypto"

// EncodeBranchNode encodes a branch node in the Merkle Patricia Trie.
//
// A branch node is represented by a 64-byte array where:
// - The first bit is 0, indicating a branch node.
// - The next 255 bits (31 bytes + 7 bits) contain the last 255 bits of the left child's hash.
// - The remaining 256 bits (32 bytes) contain the full right child's hash.
//
// Parameters:
// - left: A 32-byte array representing the hash of the left child node.
// - right: A 32-byte array representing the hash of the right child node.
//
// Returns:
// - A 64-byte array representing the encoded branch node.
func EncodeBranchNode(left, right crypto.Hash) Node {
	var node Node

	// Clear only the least significant bit of the first byte
	node[0] = left[0] & 0b01111111

	// Copy the rest of l
	copy(node[1:32], left[1:])

	// Copy all of r
	copy(node[32:], right[:])

	return node
}
