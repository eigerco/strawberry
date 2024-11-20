package trie

import (
	"bytes"
	"github.com/eigerco/strawberry/internal/crypto"
)

// Merklize computes the Merklize root hash of a list of key-value pairs, and stores the nodes if function provided.
func Merklize(keyValues [][2][]byte, i int, storeNode func(crypto.Hash, Node) error) (crypto.Hash, error) {
	// If no keys, return a zero hash
	if len(keyValues) == 0 {
		return crypto.Hash(bytes.Repeat([]byte{0}, 32)), nil
	}

	// If there's only one key, return its hash (for a leaf node)
	if len(keyValues) == 1 {
		key := keyValues[0][0]
		value := keyValues[0][1]
		var stateKey StateKey
		copy(stateKey[:], key)
		leafNode := EncodeLeafNode(stateKey, value)
		hash := crypto.HashData(leafNode[:])
		// If storeNode is provided, store the leaf node
		if storeNode != nil {
			if err := storeNode(hash, leafNode); err != nil {
				return crypto.Hash{}, err
			}
		}
		return hash, nil
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
	leftHash, err := Merklize(leftKVs, i+1, storeNode)
	if err != nil {
		return crypto.Hash{}, err
	}
	rightHash, err := Merklize(rightKVs, i+1, storeNode)
	if err != nil {
		return crypto.Hash{}, err
	}

	// Combine the two child hashes into a branch node and return its hash
	branchNode := EncodeBranchNode(leftHash, rightHash)

	hash := crypto.HashData(branchNode[:])
	// If storeNode is provided, store the branch node
	if storeNode != nil {
		if err := storeNode(hash, branchNode); err != nil {
			return crypto.Hash{}, err
		}
	}

	return hash, nil
}

// get a bit from the key
func bit(k []byte, i int) bool {
	return (k[i/8] & (1 << (7 - i%8))) != 0
}
