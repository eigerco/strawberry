package testutils

import "github.com/eigerco/strawberry/internal/crypto"

// MockHashData implements a deterministic hash function for testing
func MockHashData(data []byte) crypto.Hash {
	var hash crypto.Hash
	copy(hash[:], data)
	return hash
}
