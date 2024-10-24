package trie

import (
	"bytes"
	"github.com/eigerco/strawberry/internal/crypto"
)

// Merklize computes the Merklize root hash of a list of key-value pairs
func Merklize(keyValues [][2][]byte, i int) crypto.Hash {
	// If no keys, return a zero hash
	if len(keyValues) == 0 {
		return crypto.Hash(bytes.Repeat([]byte{0}, 32))
	}

	// If there's only one key, return its hash (for a leaf node)
	if len(keyValues) == 1 {
		key := keyValues[0][0]
		value := keyValues[0][1]
		leafNode := EncodeLeafNode(StateKey(key), value)
		return crypto.HashData(leafNode[:])
	}

	// Split the keys into left and right branches based on the current bit index
	var leftKVs, rightKVs [][2][]byte
	for _, kv := range keyValues {
		if bit(kv[0], i) {
			rightKVs = append(rightKVs, kv)
		} else {
			leftKVs = append(leftKVs, kv)
		}
	}

	// Recursively compute the left and right branch hashes
	leftHash := Merklize(leftKVs, i+1)
	rightHash := Merklize(rightKVs, i+1)

	// Combine the two child hashes into a branch node and return its hash
	branchNode := EncodeBranchNode(leftHash, rightHash)

	return crypto.HashData(branchNode[:])
}

// get a bit from the key
func bit(k []byte, i int) bool {
	return (k[i/8] & (1 << (7 - i%8))) != 0
}
