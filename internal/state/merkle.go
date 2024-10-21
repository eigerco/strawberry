package state

import (
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/merkle"
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
	rootHash := merklize(serializedState, keys, 0)
	return rootHash, nil
}

// merklize builds a Merkle tree recursively
func merklize(serializedState map[crypto.Hash][]byte, keys []crypto.Hash, bitIndex int) crypto.Hash {
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
		return crypto.HashData(reverseBitsInByteArray(leafNode[:]))
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
	leftHash := merklize(serializedState, leftKeys, bitIndex+1)
	rightHash := merklize(serializedState, rightKeys, bitIndex+1)

	// Combine the two child hashes into a branch node
	branchNode := merkle.EncodeBranchNode(leftHash, rightHash)
	// Hash the branch node
	return crypto.HashData(reverseBitsInByteArray(branchNode[:]))
}

// getBit extracts the bit at the given position in the byte array
func getBit(data []byte, bitIndex int) byte {
	byteIndex := bitIndex / 8
	bitPosition := bitIndex % 8
	return (data[byteIndex] >> (7 - bitPosition)) & 1
}

// reverseBitsInByte reverses the bits in a single byte
func reverseBitsInByte(b byte) byte {
	var reversed byte
	for i := 0; i < 8; i++ {
		reversed = (reversed << 1) | (b & 1) // Shift the reversed byte and extract the LSB of b
		b >>= 1                              // Shift b to the right to process the next bit
	}
	return reversed
}

// reverseBitsInByteArray reverses the bits in each byte of a byte array
func reverseBitsInByteArray(arr []byte) []byte {
	for i := range arr {
		arr[i] = reverseBitsInByte(arr[i]) // Reverse bits in each byte
	}
	return arr
}
