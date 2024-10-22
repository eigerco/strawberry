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

	// Convert the serialized state map to the key-value format that Merklize expects
	var kvs [][2][]byte
	for key, value := range serializedState {
		kvs = append(kvs, [2][]byte{key[:], value})
	}

	// Compute the Merkle root
	rootHash := merkle.Merklize(kvs, 0)
	return rootHash, nil
}
