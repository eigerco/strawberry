package merkle

import (
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/merkle/trie"
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

func MerklizeStateOnly(s state.State) (crypto.Hash, error) {
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

	root, err := trie.Merklize(kvs, 0,
		func(hash crypto.Hash, node trie.Node) error { return nil },
		func(value []byte) error { return nil })
	if err != nil {
		return crypto.Hash{}, err
	}

	return root, nil
}
