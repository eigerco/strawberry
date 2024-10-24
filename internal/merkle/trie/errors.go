package trie

import "errors"

var (
	ErrNotLeafNode                  = errors.New("node is not a leaf node")
	ErrNotBranchNode                = errors.New("node is not a branch node")
	ErrNotEmbeddedLeaf              = errors.New("node is not an embedded-value leaf node")
	ErrEmbeddedLeafInsteadOfRegular = errors.New("node is an embedded leaf, expected regular leaf")
)
