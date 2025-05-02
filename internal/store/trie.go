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
		if leftHash != (crypto.Hash{}) {
			if err := t.deleteNode(leftHash, false); err != nil {
				return fmt.Errorf("failed to delete left child: %v", err)
			}
		}

		// Delete right child if not empty
		if rightHash != (crypto.Hash{}) {
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

// FetchStateTrieRange retrieves a range of key-value pairs from the trie starting at startKey and ending at or before endKey.
// It also returns boundary nodes covering the paths from root to the start key and to the last key in the response.
// The response size is limited to maxSize bytes, unless the response contains only a single key/value pair.
func (t *Trie) FetchStateTrieRange(rootHash crypto.Hash, startKey, endKey [31]byte, maxSize uint32) (keys [][31]byte, values [][]byte, boundaryNodes []trie.Node, err error) {
	// Check if startKey > endKey, return empty result
	if bytesGreaterThan(startKey[:], endKey[:]) {
		return [][31]byte{}, [][]byte{}, []trie.Node{}, nil
	}

	// Initialize result collections
	keys = make([][31]byte, 0)
	values = make([][]byte, 0)

	// Map to store all nodes we encounter during traversal
	allNodes := make(map[crypto.Hash]trie.Node)

	// Track paths to first key and current last key (for boundary nodes)
	var firstKeyPath []crypto.Hash
	var lastKeyPath []crypto.Hash
	var previousLastKeyPath []crypto.Hash // Track the previous last key path for backtracking

	// Use a stack for iterative traversal (DFS approach ensures in-order traversal)
	type stackItem struct {
		nodeHash crypto.Hash
		path     []crypto.Hash // Track path from root to this node
		depth    int
	}

	stack := []stackItem{{
		nodeHash: rootHash,
		path:     []crypto.Hash{rootHash},
		depth:    0,
	}}

	for len(stack) > 0 {
		// Pop from stack (DFS)
		current := stack[len(stack)-1]
		stack = stack[:len(stack)-1]

		// Get the current node
		node, err := t.GetNode(current.nodeHash)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("failed to get node %x: %w", current.nodeHash, err)
		}

		// Store the node
		allNodes[current.nodeHash] = node

		if node.IsLeaf() {
			leafKey, err := node.GetLeafKey()
			if err != nil {
				return nil, nil, nil, fmt.Errorf("failed to get leaf key: %w", err)
			}

			var key31 [31]byte
			copy(key31[:], leafKey[:31])

			// Check if key is in our range
			if bytesGreaterOrEqual(key31[:], startKey[:]) && bytesLessOrEqual(key31[:], endKey[:]) {
				// Get the value
				var valueData []byte

				if node.IsEmbeddedLeaf() {
					valueData, err = node.GetLeafValue()
					if err != nil {
						return nil, nil, nil, fmt.Errorf("failed to get embedded leaf value: %w", err)
					}
				} else {
					valueHash, err := node.GetLeafValueHash()
					if err != nil {
						return nil, nil, nil, fmt.Errorf("failed to get leaf value hash: %w", err)
					}
					valueData, err = t.getValue(valueHash)
					if err != nil {
						return nil, nil, nil, fmt.Errorf("failed to get value for hash %x: %w", valueHash, err)
					}
				}

				// Add the key-value pair
				keys = append(keys, key31)
				values = append(values, valueData)

				// Track path for boundary nodes
				if len(keys) == 1 {
					// This is the first key - save its path
					firstKeyPath = make([]crypto.Hash, len(current.path))
					copy(firstKeyPath, current.path)
				}

				// Save the previous last key path before updating
				if len(keys) > 1 {
					previousLastKeyPath = make([]crypto.Hash, len(lastKeyPath))
					copy(previousLastKeyPath, lastKeyPath)
				}

				// Always update last key path
				lastKeyPath = make([]crypto.Hash, len(current.path))
				copy(lastKeyPath, current.path)

				// Check if we've exceeded max size
				// Calculate total response size including boundary nodes
				tempBoundaryNodes := extractBoundaryNodes(firstKeyPath, lastKeyPath, allNodes)
				tempSize := calculateResponseSize(keys, values, tempBoundaryNodes)

				// Check if adding this pair would exceed maxSize and we have more than one key
				if tempSize > maxSize && len(keys) > 1 {
					// Remove the last key-value pair we just added
					keys = keys[:len(keys)-1]
					values = values[:len(values)-1]

					// Restore the previous lastKeyPath
					if len(previousLastKeyPath) > 0 {
						lastKeyPath = previousLastKeyPath
					} else {
						// If we only had one key before adding this one, then use firstKeyPath
						lastKeyPath = firstKeyPath
					}

					// Break out of the loop - we've hit our size limit
					break
				}
			}

			// Early termination: if we've passed the end key, we can stop
			if bytesGreaterThan(key31[:], endKey[:]) {
				break
			}

			continue
		}

		// For branch nodes
		leftHash, rightHash, err := node.GetBranchHashes()
		if err != nil {
			return nil, nil, nil, fmt.Errorf("failed to get branch hashes: %w", err)
		}

		// Process right child first (will be processed after left since we're using a stack)
		if rightHash != (crypto.Hash{}) {
			rightPath := make([]crypto.Hash, len(current.path)+1)
			copy(rightPath, current.path)
			rightPath[len(current.path)] = rightHash

			stack = append(stack, stackItem{
				nodeHash: rightHash,
				path:     rightPath,
				depth:    current.depth + 1,
			})
		}

		// Process left child
		if leftHash != (crypto.Hash{}) {
			leftPath := make([]crypto.Hash, len(current.path)+1)
			copy(leftPath, current.path)
			leftPath[len(current.path)] = leftHash

			stack = append(stack, stackItem{
				nodeHash: leftHash,
				path:     leftPath,
				depth:    current.depth + 1,
			})
		}
	}

	// Extract final boundary nodes
	boundaryNodes = extractBoundaryNodes(firstKeyPath, lastKeyPath, allNodes)

	return keys, values, boundaryNodes, nil
}

// extractBoundaryNodes creates a slice of boundary nodes from the given paths
func extractBoundaryNodes(firstKeyPath, lastKeyPath []crypto.Hash, allNodes map[crypto.Hash]trie.Node) []trie.Node {
	// Use a map to eliminate duplicates
	nodeSet := make(map[crypto.Hash]struct{})

	// Add nodes on the path to first key
	for _, hash := range firstKeyPath {
		nodeSet[hash] = struct{}{}
	}

	// Add nodes on the path to last key
	for _, hash := range lastKeyPath {
		nodeSet[hash] = struct{}{}
	}

	// Convert the node set to a slice, maintaining parent-before-child relationship
	// To ensure this, we process the paths level by level from root to leaf
	var result []trie.Node

	// Find the max depth of either path
	maxDepth := max(len(firstKeyPath), len(lastKeyPath))

	// Process level by level - corrected for loop
	for depth := range maxDepth {
		// Process first path at this depth
		if depth < len(firstKeyPath) {
			hash := firstKeyPath[depth]
			// Check if we've already added this node
			if _, exists := nodeSet[hash]; exists {
				// Add the node and remove from set
				if node, nodeExists := allNodes[hash]; nodeExists {
					result = append(result, node)
				}
				delete(nodeSet, hash)
			}
		}

		// Process last path at this depth
		if depth < len(lastKeyPath) {
			hash := lastKeyPath[depth]
			// Check if we've already added this node
			if _, exists := nodeSet[hash]; exists {
				// Add the node and remove from set
				if node, nodeExists := allNodes[hash]; nodeExists {
					result = append(result, node)
				}
				delete(nodeSet, hash)
			}
		}
	}

	return result
}

// calculateResponseSize calculates the total size of the response in bytes, including key/value pairs and boundary nodes
func calculateResponseSize(keys [][31]byte, values [][]byte, nodes []trie.Node) uint32 {
	var size uint32 = 0

	// Size of the boundary nodes
	// Add 4 bytes for the length prefix of the nodes array
	size += 4 // Array length prefix
	for _, node := range nodes {
		size += uint32(len(node))
	}

	// Size of the key/value pairs
	// Add 4 bytes for the length prefix of the key/value array
	size += 4 // Array length prefix
	for i := range keys {
		size += 31                     // Key size
		size += 4                      // Value length prefix
		size += uint32(len(values[i])) // Value size
	}

	return size
}

// bytesGreaterOrEqual returns true if a >= b
func bytesGreaterOrEqual(a, b []byte) bool {
	return bytesCompare(a, b) >= 0
}

// bytesLessOrEqual returns true if a <= b
func bytesLessOrEqual(a, b []byte) bool {
	return bytesCompare(a, b) <= 0
}

// bytesGreaterThan returns true if a > b
func bytesGreaterThan(a, b []byte) bool {
	return bytesCompare(a, b) > 0
}

// bytesLessThan returns true if a < b
func bytesLessThan(a, b []byte) bool {
	return bytesCompare(a, b) < 0
}

// bytesCompare compares two byte slices lexicographically
func bytesCompare(a, b []byte) int {
	length := len(a)
	length = min(length, len(b))

	for i := range length {
		if a[i] < b[i] {
			return -1
		}
		if a[i] > b[i] {
			return 1
		}
	}

	if len(a) < len(b) {
		return -1
	}
	if len(a) > len(b) {
		return 1
	}
	return 0
}
