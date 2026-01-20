package trie

import (
	"github.com/eigerco/strawberry/internal/crypto"
)

// Merklize computes the Merklize root hash of a list of key-value pairs, and stores the nodes if function provided.
func Merklize(keyValues [][2][]byte, i int, storeNode func(crypto.Hash, Node) error, storeValue func([]byte) error) (crypto.Hash, error) {
	// If no keys, return a zero hash
	if len(keyValues) == 0 {
		return crypto.Hash{}, nil
	}

	// If there's only one key, return its hash (for a leaf node)
	if len(keyValues) == 1 {
		key := keyValues[0][0]
		value := keyValues[0][1]
		var stateKey StateKey
		copy(stateKey[:], key)

		// If it is a regualar leaf (the value is too big to be embedded), store the value
		if len(value) > EmbeddedValueMaxSize && storeValue != nil {
			err := storeValue(value)
			if err != nil {
				return crypto.Hash{}, err
			}
		}

		leafNode := EncodeLeafNode(stateKey, value)
		hash := crypto.HashData(leafNode[:])

		if storeNode != nil {
			if err := storeNode(hash, leafNode); err != nil {
				return crypto.Hash{}, err
			}
		}
		return hash, nil
	}

	// Partition in-place: items with bit=0 go to the left, bit=1 go to the right.
	// This avoids allocating new slices at each recursion level.
	pivot := partitionByBit(keyValues, i)

	// Recursively compute the left and right branch hashes
	leftHash, err := Merklize(keyValues[:pivot], i+1, storeNode, storeValue)
	if err != nil {
		return crypto.Hash{}, err
	}
	rightHash, err := Merklize(keyValues[pivot:], i+1, storeNode, storeValue)
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

// partitionByBit partitions keyValues in-place based on the bit at index i.
// Returns the pivot index where left partition ends (all items with bit=0 are before pivot).
func partitionByBit(keyValues [][2][]byte, i int) int {
	left := 0
	for right := range keyValues {
		if !bit(keyValues[right][0], i) {
			keyValues[left], keyValues[right] = keyValues[right], keyValues[left]
			left++
		}
	}
	return left
}

// get a bit from the key
func bit(k []byte, i int) bool {
	return (k[i/8] & (1 << (7 - i%8))) != 0
}
