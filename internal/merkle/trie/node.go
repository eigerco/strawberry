package trie

import "github.com/eigerco/strawberry/internal/crypto"

const (
	// NodeSize is the size of a node in bytes.
	// It is set to 64 bytes (512 bits) as per the graypaper specification.
	NodeSize = 64 // 512 bits

	// LeafNodeFlag indicates a leaf node.
	LeafNodeFlag byte = 0b10000000

	// NotEmbeddedLeafFlag indicates an embedded leaf node.
	NotEmbeddedLeafFlag byte = 0b01000000

	// ValueSizeMask extracts the embedded value size.
	ValueSizeMask byte = 0b00111111

	EmbeddedValueMaxSize = 32

	// StateKeySize is the size of a state key in bytes.
	StateKeySize = 32
)

// StateKey is a fixed-size byte array representing a key in the state trie.
type StateKey [StateKeySize]byte

// StateValue is a variable-length byte slice representing a value in the state trie.
type StateValue []byte

// Node represents a node in the Merkle Patricia Trie.
type Node [NodeSize]byte

// IsLeaf returns true if the node is a leaf node, false otherwise.
// A node is a leaf if its first bit is 1.
func (n Node) IsLeaf() bool {
	return n[0]&LeafNodeFlag != 0
}

// IsBranch returns true if the node is a branch node, false otherwise.
// A node is a branch if its first bit is 0.
func (n Node) IsBranch() bool {
	return n[0]&LeafNodeFlag == 0
}

// IsEmbeddedLeaf returns true if the node is an embedded-value leaf node, false otherwise.
// A node is an embedded-value leaf if it's a leaf and its second bit is 1.
func (n Node) IsEmbeddedLeaf() bool {
	return n.IsLeaf() && n[0]&NotEmbeddedLeafFlag == 0
}

// GetEmbeddedValueSize returns the size of the embedded value if the node is an embedded-value leaf.
func (n Node) GetEmbeddedValueSize() (int, error) {
	if !n.IsEmbeddedLeaf() {
		return 0, ErrNotEmbeddedLeaf
	}
	return int(n[0] & ValueSizeMask), nil
}

// GetBranchHashes retrieves both the left and right hashes from a branch node.
// It returns two Hash values and a boolean indicating success.
// For the left hash, we ignore the first byte of the node (which is the node type identifier)
func (n Node) GetBranchHashes() (crypto.Hash, crypto.Hash, error) {
	if !n.IsBranch() {
		return crypto.Hash{}, crypto.Hash{}, ErrNotBranchNode
	}

	var left, right crypto.Hash

	// Extract left hash
	copy(left[:], n[1:32])
	// Extract right hash
	copy(right[:], n[32:])

	return left, right, nil
}

// GetLeafKey retrieves the key from a leaf node.
func (n Node) GetLeafKey() (StateKey, error) {
	if !n.IsLeaf() {
		return StateKey{}, ErrNotLeafNode
	}

	var key StateKey
	copy(key[:], n[1:32])
	return key, nil
}

// GetLeafValue retrieves the value from an embedded-value leaf node.
func (n Node) GetLeafValue() ([]byte, error) {
	size, err := n.GetEmbeddedValueSize()
	if err != nil {
		return nil, err
	}
	value := make([]byte, size)
	copy(value, n[32:32+size])
	return value, nil
}

// GetLeafValueHash retrieves the value hash from a regular leaf node.
func (n Node) GetLeafValueHash() (crypto.Hash, error) {
	if !n.IsLeaf() {
		return crypto.Hash{}, ErrNotLeafNode
	}
	if n.IsEmbeddedLeaf() {
		return crypto.Hash{}, ErrEmbeddedLeafInsteadOfRegular
	}
	var hash crypto.Hash
	copy(hash[:], n[StateKeySize:])
	return hash, nil
}
