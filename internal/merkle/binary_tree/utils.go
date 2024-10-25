package binary_tree

import "github.com/eigerco/strawberry/internal/crypto"

// convertHashToBlob explicitly converts the Hash to a blob
func convertHashToBlob(h crypto.Hash) []byte {
	return h[:]
}

func convertBlobsToHashes(blobs [][]byte) []crypto.Hash {
	result := make([]crypto.Hash, len(blobs))
	for i, blob := range blobs {
		copy(result[i][:], blob)
	}
	return result
}
