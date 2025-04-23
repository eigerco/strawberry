package store

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/merkle/trie"
	"github.com/eigerco/strawberry/pkg/db"
	"github.com/eigerco/strawberry/pkg/db/pebble"
)

const (
	// ErrNotLeafNode is returned when a non-leaf node is used where a leaf is expected
	ErrNotLeafNode = "not a leaf node"
)

type Trie struct {
	db.KVStore
}

func NewTrie(store db.KVStore) *Trie {
	return &Trie{KVStore: store}
}

// MerklizeAndCommit writes a series of key-value pairs to the trie
func (t *Trie) MerklizeAndCommit(pairs [][2][]byte) (crypto.Hash, error) {
	batch := t.NewBatch()

	// Keep track of new nodes to increment ref counts after commit
	var newNodes []crypto.Hash

	root, err := trie.Merklize(pairs, 0,
		func(hash crypto.Hash, node trie.Node) error {
			newNodes = append(newNodes, hash)
			return batch.Put(makeKey(prefixTrieNode, hash[1:]), node[:])
		},
		func(value []byte) error {
			hash := crypto.HashData(value)
			return batch.Put(makeKey(prefixTrieNodeValue, hash[:]), value)
		})

	// Handle the Merklize error before committing
	if err != nil {
		closeErr := batch.Close()
		if closeErr != nil {
			return crypto.Hash{}, fmt.Errorf("merklize error: %v, failed to close batch: %v", err, closeErr)
		}
		return crypto.Hash{}, fmt.Errorf("merklize error: %v", err)
	}

	// Commit the batch
	if err := batch.Commit(); err != nil {
		closeErr := batch.Close()
		if closeErr != nil {
			// Handle the case where both commit and close fail
			return crypto.Hash{}, fmt.Errorf("commit error: %v, close error: %v", err, closeErr)
		}
		return crypto.Hash{}, fmt.Errorf("commit error: %v", err)
	}

	// Close the batch after successful commit
	if err := batch.Close(); err != nil {
		return crypto.Hash{}, fmt.Errorf(ErrFailedBatchCommit, err)
	}

	// Increment ref counts for new nodes
	for _, hash := range newNodes {
		if err := t.IncreaseNodeRefCount(hash); err != nil {
			return crypto.Hash{}, fmt.Errorf("failed to increase ref count for hash %x: %v", hash, err)
		}
	}

	return root, nil
}

// Get retrieves a node from the database using its hash
func (t *Trie) GetNode(hash crypto.Hash) (trie.Node, error) {
	data, err := t.Get(makeKey(prefixTrieNode, hash[1:]))
	if err != nil {
		if errors.Is(err, pebble.ErrNotFound) {
			return trie.Node{}, pebble.ErrNotFound // Return the specific error
		}
		return trie.Node{}, fmt.Errorf("failed to get hash %x: %v", hash, err)
	}
	return trie.Node(data), nil
}

// GetNodeValue retrieves the value from a node /regular and embedded leaf/
func (t *Trie) GetNodeValue(node trie.Node) ([]byte, error) {
	if !node.IsLeaf() {
		return nil, errors.New(ErrNotLeafNode)
	}

	if node.IsEmbeddedLeaf() {
		// For embedded leaf, the value is in the node
		return node.GetLeafValue()
	} else {
		// For regular leaf, get the value hash and then retrieve the value
		valueHash, err := node.GetLeafValueHash()
		if err != nil {
			return nil, err
		}

		return t.getValue(valueHash)
	}
}

// getValue retrieves the value of a regular leaf from the database using the hash
func (t *Trie) getValue(hash crypto.Hash) ([]byte, error) {
	value, err := t.Get(makeKey(prefixTrieNodeValue, hash[:]))
	if err != nil {
		if errors.Is(err, pebble.ErrNotFound) {
			return nil, pebble.ErrNotFound
		}
		return nil, fmt.Errorf("failed to get value for hash %x: %v", hash, err)
	}

	return value, nil
}

// IncreaseNodeRefCount increments the reference count for a node
func (t *Trie) IncreaseNodeRefCount(hash crypto.Hash) error {
	key := makeKey(prefixTrieNodeRefCount, hash[1:])
	currentCount, err := t.Get(key)

	var newCount uint64
	if err == nil {
		// Node exists, increment count
		currentCountVal := binary.LittleEndian.Uint64(currentCount)
		newCount = currentCountVal + 1
	} else if errors.Is(err, pebble.ErrNotFound) {
		// First reference to this node
		newCount = 1
	} else {
		// Unexpected error
		return fmt.Errorf("failed to get ref count for hash %x: %v", hash, err)
	}

	countBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(countBytes, newCount)

	return t.Put(key, countBytes)
}

// DecreaseNodeRefCount decrements the reference count for a node
// Returns the new count and any error
func (t *Trie) DecreaseNodeRefCount(hash crypto.Hash) (uint64, error) {
	key := makeKey(prefixTrieNodeRefCount, hash[1:])
	currentCount, err := t.Get(key)
	if err != nil {
		if errors.Is(err, pebble.ErrNotFound) {
			return 0, fmt.Errorf("ref count not found for hash %x", hash)
		}
		return 0, fmt.Errorf("failed to get ref count for hash %x: %v", hash, err)
	}

	currentCountVal := binary.LittleEndian.Uint64(currentCount)
	if currentCountVal == 0 {
		return 0, fmt.Errorf("ref count already zero for hash %x", hash)
	}

	newCount := currentCountVal - 1
	countBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(countBytes, newCount)

	err = t.Put(key, countBytes)
	if err != nil {
		return 0, fmt.Errorf("failed to update ref count for hash %x: %v", hash, err)
	}

	return newCount, nil
}

// TrieExists checks if a trie with the given root hash exists
func (t *Trie) TrieExists(rootHash crypto.Hash) (bool, error) {
	_, err := t.GetNode(rootHash)
	if err != nil {
		if errors.Is(err, pebble.ErrNotFound) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// GetNodeRefCount returns the reference count for a node /how many nodes links to this one (how many tries)/.
func (t *Trie) GetNodeRefCount(hash crypto.Hash) (uint64, error) {
	key := makeKey(prefixTrieNodeRefCount, hash[1:])
	data, err := t.Get(key)
	if err != nil {
		return 0, err
	}

	return binary.LittleEndian.Uint64(data), nil
}

// DeleteTrie deletes a trie from the database starting from the root hash
func (t *Trie) DeleteTrie(rootHash crypto.Hash) error {
	return t.deleteNode(rootHash, true)
}

// deleteNode recursively deletes a node and its children
// The forceDelete parameter controls whether to delete the node regardless of its reference count
func (t *Trie) deleteNode(hash crypto.Hash, forceDelete bool) error {
	// Get the node
	node, err := t.GetNode(hash)
	if err != nil {
		if errors.Is(err, pebble.ErrNotFound) {
			// Node already deleted, nothing to do
			return nil
		}
		return fmt.Errorf("failed to get node %x: %v", hash, err)
	}

	// Decrease reference count
	newCount, err := t.DecreaseNodeRefCount(hash)
	if err != nil {
		return fmt.Errorf("failed to decrease ref count for hash %x: %v", hash, err)
	}

	// If reference count is still > 0 and we're not forcing deletion, stop here
	if newCount > 0 && !forceDelete {
		return nil
	}

	// Delete based on node type
	if node.IsBranch() {
		// For branch nodes, recursively delete children
		leftHash, rightHash, err := node.GetBranchHashes()
		if err != nil {
			return fmt.Errorf("failed to get branch hashes: %v", err)
		}

		// Delete left child if not empty
		if !isZeroHash(leftHash) {
			if err := t.deleteNode(leftHash, false); err != nil {
				return fmt.Errorf("failed to delete left child: %v", err)
			}
		}

		// Delete right child if not empty
		if !isZeroHash(rightHash) {
			if err := t.deleteNode(rightHash, false); err != nil {
				return fmt.Errorf("failed to delete right child: %v", err)
			}
		}
	} else if node.IsLeaf() {
		// For leaf nodes, delete the value if it's a regular leaf
		if !node.IsEmbeddedLeaf() {
			valueHash, err := node.GetLeafValueHash()
			if err != nil {
				return fmt.Errorf("failed to get leaf value hash: %v", err)
			}

			// Delete the value
			if err := t.Delete(makeKey(prefixTrieNodeValue, valueHash[:])); err != nil {
				return fmt.Errorf("failed to delete value for hash %x: %v", valueHash, err)
			}
		}
	}

	// Delete the node itself and its reference count
	if err := t.Delete(makeKey(prefixTrieNode, hash[1:])); err != nil {
		if !errors.Is(err, pebble.ErrNotFound) {
			return fmt.Errorf("failed to delete node %x: %v", hash, err)
		}
		// Node already deleted, continue
	}

	if err := t.Delete(makeKey(prefixTrieNodeRefCount, hash[1:])); err != nil {
		if !errors.Is(err, pebble.ErrNotFound) {
			return fmt.Errorf("failed to delete ref count for hash %x: %v", hash, err)
		}
		// Ref count already deleted, continue
	}

	return nil
}

// isZeroHash checks if a hash is all zeros
func isZeroHash(hash crypto.Hash) bool {
	for _, b := range hash {
		if b != 0 {
			return false
		}
	}
	return true
}
