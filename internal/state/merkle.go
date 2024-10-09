package state

import (
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/merkle"
	"golang.org/x/crypto/blake2b"
)

// MerklizeState computes the Merkle root of a given state.
func MerklizeState(s State) (crypto.Hash, error) {
	// Serialize the state
	serializedState, err := SerializeState(s)
	if err != nil {
		return crypto.Hash{}, err
	}

	// Collect the keys
	var keys []crypto.Hash
	for key := range serializedState {
		keys = append(keys, key)
	}

	// Recursively compute the Merkle root
	rootHash := merklizeRecursive(serializedState, keys, 0)
	return rootHash, nil
}

// merklizeRecursive builds a Merkle tree recursively
func merklizeRecursive(serializedState map[crypto.Hash][]byte, keys []crypto.Hash, bitIndex int) crypto.Hash {
	// If empty, return a zero hash
	if len(keys) == 0 {
		return crypto.Hash{}
	}

	// If there's only one key, return its hash (for a leaf node)
	if len(keys) == 1 {
		key := keys[0]
		value := serializedState[key]

		// Encode the leaf node
		leafNode := merkle.EncodeLeafNode(merkle.StateKey(key), value)
		// Hash the leaf node
		return blake2b.Sum256(leafNode[:])
	}

	// Split keys into left and right based on the current bit
	var leftKeys, rightKeys []crypto.Hash
	for _, key := range keys {
		if getBit(key[:], bitIndex) == 0 {
			leftKeys = append(leftKeys, key)
		} else {
			rightKeys = append(rightKeys, key)
		}
	}

	// Compute hashes for both halves
	leftHash := merklizeRecursive(serializedState, leftKeys, bitIndex+1)
	rightHash := merklizeRecursive(serializedState, rightKeys, bitIndex+1)

	// Combine the two child hashes into a branch node
	branchNode := merkle.EncodeBranchNode(leftHash, rightHash)
	// Hash the branch node
	return blake2b.Sum256(branchNode[:])
}

// getBit extracts the bit at the given position in the byte array
func getBit(data []byte, bitIndex int) byte {
	byteIndex := bitIndex / 8
	bitPosition := bitIndex % 8
	return (data[byteIndex] >> (7 - bitPosition)) & 1
}
