package merkle

import (
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/state"
	"github.com/eigerco/strawberry/internal/state/serialization"
	"github.com/eigerco/strawberry/internal/store"
)

// MerklizeState computes the Merkle root of a given state.
func MerklizeState(s state.State, store *store.Trie) (crypto.Hash, error) {
	// Serialize the state
	serializedState, err := serialization.SerializeState(s)
	if err != nil {
		return crypto.Hash{}, err
	}

	// Convert the serialized state map to the key-value format that Merklize expects
	var kvs [][2][]byte
	for key, value := range serializedState {
		kvs = append(kvs, [2][]byte{key[:], value})
	}

	// Compute the Merkle root and store trie nodes in the database
	rootHash, err := store.MerklizeAndCommit(kvs)
	if err != nil {
		return crypto.Hash{}, err
	}
	return rootHash, nil
}
