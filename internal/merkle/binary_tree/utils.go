package binary_tree

import "github.com/eigerco/strawberry/internal/crypto"

// convertHashToSlice explicitly converts the Hash to a byte slice
func convertHashToSlice(h crypto.Hash) []byte {
	return h[:]
}
