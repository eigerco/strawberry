package merkle

import (
	"fmt"
	"github.com/eigerco/strawberry/pkg/serialization"
	"github.com/eigerco/strawberry/pkg/serialization/codec"
	"golang.org/x/crypto/blake2b"
)

// EncodeLeafNode encodes a leaf node in the Merkle Patricia Trie.
//
// A leaf node is represented by a 64-byte array where:
// - The first bit is 1, indicating a leaf node.
// - The second bit indicates the leaf type: 1 for embedded-value, 0 for regular.
// - For embedded-value leaves (value <= 32 bytes):
//   - The remaining 6 bits of the first byte store the encoded value's length.
//   - The next 31 bytes store the first 31 bytes of the key.
//   - The last 32 bytes store the value, zero-padded if less than 32 bytes.
//
// - For regular leaves (value > 32 bytes):
//   - The remaining 6 bits of the first byte are zeroed.
//   - The next 31 bytes store the first 31 bytes of the key.
//   - The last 32 bytes store the hash of the value.
//
// Parameters:
// - key: A 32-byte array representing the full key.
// - value: A byte slice containing the value to be stored.
//
// Returns:
// - A 64-byte array representing the encoded leaf node.
func EncodeLeafNode(key StateKey, value StateValue) Node {
	var node Node

	if len(value) <= EmbeddedValueMaxSize {
		jamCodec := codec.NewJamCodec()
		serializer := serialization.NewSerializer(jamCodec)
		encodedValueLength, err := serializer.Encode(len(value))
		if err != nil {
			panic(fmt.Sprintf("state value should always be encodable: %v", err))
		}
		if len(encodedValueLength) != 1 {
			panic(fmt.Sprintf("encoded value length should be one byte: %v", len(encodedValueLength)))
		}

		// Embedded-value leaf
		node[0] = LeafNodeFlag | EmbeddedLeafFlag | encodedValueLength[0] // 1000 0000 | 0100 0000 | encoded value length
		copy(node[1:32], key[:31])                                        // First 31 bytes of key
		copy(node[32:], value)                                            // Value (up to 32 bytes)
	} else {
		// Regular leaf
		node[0] = LeafNodeFlag     // 1000 0000
		copy(node[1:32], key[:31]) // First 31 bytes of key
		hash := blake2b.Sum256(value)
		copy(node[32:], hash[:]) // Hash of the value
	}

	return node
}