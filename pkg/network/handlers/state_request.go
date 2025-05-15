package handlers

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"fmt"
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/merkle/trie"
	"github.com/eigerco/strawberry/internal/store"
	"github.com/eigerco/strawberry/pkg/serialization/codec/jam"
	"github.com/quic-go/quic-go"
)

const (
	hashSize         = crypto.HashSize
	keySize          = 31
	maxSizeSize      = 4
	headerHashOffset = 0
	keyStartOffset   = headerHashOffset + hashSize
	keyEndOffset     = keyStartOffset + keySize
	maxSizeOffset    = keyEndOffset + keySize
)

// StateRequestHandler processes incoming state request streams according to the CE 129 protocol.
// It provides access to the trie data structure that stores the blockchain state.
type StateRequestHandler struct {
	trie *store.Trie // The state trie store containing key-value pairs
}

// NewStateRequestHandler creates a new handler for processing state requests.
// It takes a reference to a store.Trie that will be used to serve state data.
func NewStateRequestHandler(trie *store.Trie) *StateRequestHandler {
	return &StateRequestHandler{
		trie: trie,
	}
}

// stateRequestMessage represents the structure of an incoming state request.
type stateRequestMessage struct {
	HeaderHash crypto.Hash   // The hash of the block header whose state is being requested
	KeyStart   [keySize]byte // The first key in the requested range (inclusive)
	KeyEnd     [keySize]byte // The last key in the requested range (inclusive)
	MaxSize    uint32        // Maximum size in bytes for the response
}

// HandleStream processes an incoming state request stream according to CE 129 protocol.
// Key = [u8; 31] (First 31 bytes of key only)
// Maximum Size = u32
// Boundary Node = As returned by B/L, defined in the State Merklization appendix of the GP
// Value = len++[u8]
// Node -> Node
// --> Header Hash ++ Key (Start) ++ Key (End) ++ Maximum Size
// --> FIN
// <-- [Boundary Node]
// <-- [Key ++ Value]
// <-- FIN
func (h *StateRequestHandler) HandleStream(ctx context.Context, stream quic.Stream, peerKey ed25519.PublicKey) error {
	// Read the request message
	msg, err := ReadMessageWithContext(ctx, stream)
	if err != nil {
		return fmt.Errorf("read request message: %w", err)
	}
	// Validate minimum message length:
	// 32 bytes for HeaderHash, 31 bytes for KeyStart, 31 bytes for KeyEnd, and 4 bytes for MaxSize
	if len(msg.Content) < crypto.HashSize+keySize+keySize+4 {
		return fmt.Errorf("message too short")
	}

	// Decode the MaxSize as a little-endian uint32
	maxSize := binary.LittleEndian.Uint32(msg.Content[maxSizeOffset : maxSizeOffset+maxSizeSize])

	// Validate the MaxSize
	if maxSize == 0 {
		return fmt.Errorf("invalid MaxSize: %d", maxSize)
	}
	// Parse the full message into our struct
	trieRangeMessage := &stateRequestMessage{
		HeaderHash: crypto.Hash(msg.Content[headerHashOffset:keyStartOffset]), // First 32 bytes are the header hash
		KeyStart:   [keySize]byte(msg.Content[keyStartOffset:keyEndOffset]),   // Next 31 bytes are the start key
		KeyEnd:     [keySize]byte(msg.Content[keyEndOffset:maxSizeOffset]),    // Next 31 bytes are the end key
		MaxSize:    maxSize,                                                   // Last 4 bytes are the max size
	}

	// Validate the range: KeyStart should be less than or equal to KeyEnd
	// This is a simple lexicographical comparison of the byte arrays
	if bytes.Compare(trieRangeMessage.KeyStart[:], trieRangeMessage.KeyEnd[:]) > 0 {
		return fmt.Errorf("invalid range: start key is greater than end key")
	}

	// Fetch the requested range from the trie
	result, err := h.trie.FetchStateTrieRange(trieRangeMessage.HeaderHash, trieRangeMessage.KeyStart, trieRangeMessage.KeyEnd, trieRangeMessage.MaxSize)
	if err != nil {
		return fmt.Errorf("fetch state trie range: %w", err)
	}

	// Write the boundary nodes as the first message in the response
	// These represent the Merkle proof paths for the range
	if err := WriteMessageWithContext(ctx, stream, serializeNodes(result.BoundaryNodes)); err != nil {
		return fmt.Errorf("write message: %w", err)
	}

	// Marshal the key-value pairs using the JAM codec
	pairs, err := jam.Marshal(result.Pairs)
	if err != nil {
		return fmt.Errorf("marshal pairs: %w", err)
	}

	// Write the key-value pairs as the second message in the response
	if err := WriteMessageWithContext(ctx, stream, pairs); err != nil {
		return fmt.Errorf("write message: %w", err)
	}
	// Close the stream to signal that we're done sending data (FIN)
	if err := stream.Close(); err != nil {
		return fmt.Errorf("close stream: %w", err)
	}

	return nil
}

// serializeNodes converts a slice of trie.Node objects to a byte slice for network transmission.
// Each node in the Patricia Merkle Trie has a fixed size (trie.NodeSize).
// The function simply concatenates all nodes together.
func serializeNodes(nodes []trie.Node) []byte {
	if len(nodes) == 0 {
		return nil
	}

	totalSize := len(nodes) * trie.NodeSize
	result := make([]byte, totalSize)

	for i, node := range nodes {
		copy(result[i*trie.NodeSize:], node[:])
	}

	return result
}

// deserializeNodes converts a byte slice back into a slice of trie.Node objects.
// The function expects the input data to be a multiple of trie.NodeSize.
//
// Parameters:
// - data: A byte slice containing concatenated node data
//
// Returns:
// - A slice of trie.Node objects
// - An error if the data length is not a multiple of trie.NodeSize
func deserializeNodes(data []byte) ([]trie.Node, error) {
	if len(data)%trie.NodeSize != 0 {
		return nil, fmt.Errorf("data length is not a multiple of trie node size")
	}

	numNodes := len(data) / trie.NodeSize
	nodes := make([]trie.Node, numNodes)

	for i := range numNodes {
		copy(nodes[i][:], data[i*trie.NodeSize:(i+1)*trie.NodeSize])
	}

	return nodes, nil
}

// StateRequester provides functionality for making state requests to other nodes.
// It implements the client side of the CE 129 protocol.
type StateRequester struct{}

// RequestState sends a state request to another node and processes the response.
// This implements the client side of the CE 129 protocol.
//
// Parameters:
// - ctx: The context for the request, used for cancellation and timeouts
// - stream: The QUIC stream for sending/receiving data
// - headerHash: The hash of the block header whose state is being requested
// - keyStart: The first key in the requested range (inclusive)
// - keyEnd: The last key in the requested range (inclusive)
// - maxSize: Maximum size in bytes for the response
//
// Returns:
// - A TrieRangeResult containing the boundary nodes and key-value pairs
// - An error if the request or response processing fails
func (h *StateRequester) RequestState(ctx context.Context, stream quic.Stream, headerHash crypto.Hash, keyStart [31]byte, keyEnd [31]byte, maxSize uint32) (store.TrieRangeResult, error) {
	// Create the request message byte array
	content := make([]byte, hashSize+keySize+keySize+maxSizeSize)
	copy(content[:keyStartOffset], headerHash[:])                   // First 32 bytes: header hash
	copy(content[keyStartOffset:keyEndOffset], keyStart[:])         // Next 31 bytes: start key
	copy(content[keyEndOffset:maxSizeOffset], keyEnd[:])            // Next 31 bytes: end key
	binary.LittleEndian.PutUint32(content[maxSizeOffset:], maxSize) // Next 4 bytes: max size as little-endian uint32

	// Send the request message
	if err := WriteMessageWithContext(ctx, stream, content); err != nil {
		return store.TrieRangeResult{}, fmt.Errorf("write request message: %w", err)
	}

	// Close our write side to signal we're done sending (FIN)
	if err := stream.Close(); err != nil {
		return store.TrieRangeResult{}, fmt.Errorf("close write: %w", err)
	}

	// Read the first response message containing boundary nodes
	msg, err := ReadMessageWithContext(ctx, stream)
	if err != nil {
		return store.TrieRangeResult{}, fmt.Errorf("read response message: %w", err)
	}

	// Check if the response is empty
	if len(msg.Content) == 0 {
		return store.TrieRangeResult{}, fmt.Errorf("empty response")
	}

	// Deserialize the boundary nodes from the first message
	boundaryNodes, err := deserializeNodes(msg.Content)
	if err != nil {
		return store.TrieRangeResult{}, fmt.Errorf("deserialize nodes: %w", err)
	}

	// Read the response message
	msg2, err := ReadMessageWithContext(ctx, stream)
	if err != nil {
		return store.TrieRangeResult{}, fmt.Errorf("read response message: %w", err)
	}

	var pairs []store.KeyValuePair

	// Unmarshal the key-value pairs using the JAM codec
	if err := jam.Unmarshal(msg2.Content, &pairs); err != nil {
		return store.TrieRangeResult{}, fmt.Errorf("unmarshal pairs: %w", err)
	}

	// Construct and return the final result
	result := store.TrieRangeResult{
		BoundaryNodes: boundaryNodes,
		Pairs:         pairs,
	}

	return result, nil
}
