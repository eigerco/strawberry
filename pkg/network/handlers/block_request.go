package handlers

import (
	"context"
	"encoding/binary"
	"fmt"

	"github.com/eigerco/strawberry/internal/block"
	"github.com/eigerco/strawberry/internal/chain"
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/pkg/serialization/codec/jam"
	"github.com/quic-go/quic-go"
)

// BlockRequestHandler processes CE 128 block request streams from peers.
// It implements protocol specification section "CE 128: Block request".
// Block requests allow peers to request sequences of blocks either:
// - Ascending from a given block (exclusive of the block itself)
// - Descending from a given block (inclusive of the block itself)
type BlockRequestHandler struct {
	blockService *chain.BlockService
}

// NewBlockRequestHandler creates a new handler for processing block requests.
// It requires a BlockService to fetch requested blocks from storage.
func NewBlockRequestHandler(blockService *chain.BlockService) *BlockRequestHandler {
	return &BlockRequestHandler{
		blockService: blockService,
	}
}

// blockRequestMessage represents the wire format for block requests.
// As per protocol spec:
// - Header Hash: Starting point for block sequence
// - Direction: 0 for ascending (exclusive), 1 for descending (inclusive)
// - MaxBlocks: Maximum number of blocks to return
type blockRequestMessage struct {
	Hash      crypto.Hash
	Direction byte // 0 for ascending, 1 for descending
	MaxBlocks uint32
}

// HandleStream processes an incoming block request stream according to CE 128 protocol.
// Message format:
//   - Header hash (32 bytes): Starting block hash
//   - Direction (1 byte): 0 for ascending exclusive, 1 for descending inclusive
//   - Maximum blocks (4 bytes): Little-endian uint32 maximum blocks to return
//
// Response format:
//   - Length-prefixed sequence of encoded blocks
//   - Stream is closed with FIN bit set after response
//
// The response sequence starts from the given block hash and follows the chain
// either forward (for ascending) or backward (for descending), limited by MaxBlocks.
// For ascending requests, the sequence starts with a child of the given block.
// For descending requests, the sequence starts with the given block itself.
func (h *BlockRequestHandler) HandleStream(ctx context.Context, stream quic.Stream) error {
	// Read the request message
	msg, err := ReadMessageWithContext(ctx, stream)
	if err != nil {
		return fmt.Errorf("failed to read request message: %w", err)
	}

	// Validate minimum message length:
	// 32 bytes (hash) + 1 byte (direction) + 4 bytes (maxBlocks) = 37 bytes
	if len(msg.Content) < 37 { // 32 (hash) + 1 (direction) + 4 (maxBlocks)
		return fmt.Errorf("message too short")
	}

	// Parse fixed-size wire format
	request := blockRequestMessage{
		Direction: msg.Content[32], // After hash
		MaxBlocks: binary.LittleEndian.Uint32(msg.Content[33:37]),
	}
	copy(request.Hash[:], msg.Content[:32])

	// Fetch block sequence based on direction
	ascending := request.Direction == 0
	blocks, err := h.blockService.Store.GetBlockSequence(request.Hash, ascending, request.MaxBlocks)
	if err != nil {
		return fmt.Errorf("failed to get blocks: %w", err)
	}

	// Marshal all blocks into a single response
	response, err := jam.Marshal(blocks)
	if err != nil {
		return fmt.Errorf("failed to marshal blocks: %w", err)
	}
	if err := WriteMessageWithContext(ctx, stream, response); err != nil {
		return fmt.Errorf("failed to write response message: %w", err)
	}
	// Close the stream to signal we're done writing (this sets the FIN bit)
	if err := stream.Close(); err != nil {
		return fmt.Errorf("failed to close stream: %w", err)
	}
	return nil
}

// BlockRequester handles outgoing CE 128 block requests to peers.
// It implements the client side of the block request protocol.
type BlockRequester struct{}

// RequestBlocks sends a block request to a peer and receives the response.
// Parameters:
//   - ctx: Context for cancellation
//   - stream: QUIC stream for the request
//   - headerHash: Hash of the starting block
//   - ascending: If true, gets blocks after header (exclusive)
//     If false, gets blocks before and including header
//   - maxBlocks: Maximum number of blocks to request
//
// The request follows CE 128 protocol format:
//
//	--> Header Hash (32 bytes) ++ Direction (1 byte) ++ Maximum Blocks (4 bytes LE)
//	--> FIN
//	<-- [Block]
//	<-- FIN
//
// Returns:
//   - Sequence of blocks if successful
//   - Error if request fails, response invalid, or context cancelled
func (r *BlockRequester) RequestBlocks(ctx context.Context, stream quic.Stream, headerHash [32]byte, ascending bool, maxBlocks uint32) ([]block.Block, error) {
	direction := byte(0)
	if !ascending {
		direction = 1
	}
	content := make([]byte, 37)
	copy(content[:32], headerHash[:])
	content[32] = direction
	binary.LittleEndian.PutUint32(content[33:], maxBlocks)

	// Write with context
	if err := WriteMessageWithContext(ctx, stream, content); err != nil {
		return nil, fmt.Errorf("failed to write request: %w", err)
	}
	// Closes only the write direction (sets FIN on our side)
	if err := stream.Close(); err != nil {
		return nil, fmt.Errorf("failed to close write: %w", err)
	}
	// Read with context
	response, err := ReadMessageWithContext(ctx, stream)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	// Unmarshal block sequence
	var blocks []block.Block
	err = jam.Unmarshal(response.Content, &blocks)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	return blocks, nil
}
