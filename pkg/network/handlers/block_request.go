package handlers

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/quic-go/quic-go"
)

// BlockRequestHandler handles incoming block requests
type BlockRequestHandler struct{}

func NewBlockRequestHandler() *BlockRequestHandler {
	return &BlockRequestHandler{}
}

// HandleStream processes incoming block requests (when others request blocks from us)
func (h *BlockRequestHandler) HandleStream(ctx context.Context, stream quic.Stream) error {
	fmt.Println("Received block request, reading request message...")

	// Read the request message
	msg, err := ReadMessageWithContext(ctx, stream)
	if err != nil {
		return fmt.Errorf("failed to read request message: %w", err)
	}

	// Parse the message content into BlockRequestMessage
	if len(msg.Content) < 37 { // 32 (hash) + 1 (direction) + 4 (maxBlocks)
		return fmt.Errorf("message too short")
	}

	request := BlockRequestMessage{
		Direction: msg.Content[32], // After hash
		MaxBlocks: binary.LittleEndian.Uint32(msg.Content[33:37]),
	}
	copy(request.Hash[:], msg.Content[:32])

	fmt.Printf("Got request for blocks: hash=%x, direction=%d, maxBlocks=%d\n",
		request.Hash, request.Direction, request.MaxBlocks)

	// Test data: Pretend to send some blocks
	response := []byte("test block response")
	if err := WriteMessageWithContext(ctx, stream, response); err != nil {
		return fmt.Errorf("failed to write response message: %w", err)
	}

	fmt.Println("Sent block response")
	return nil
}

// BlockRequester makes outgoing block requests
type BlockRequester struct{}

// TODO: Implement the RequestBlocks function
// RequestBlocks sends a request for blocks to a peer
func (r *BlockRequester) RequestBlocks(ctx context.Context, stream io.ReadWriter, headerHash [32]byte, ascending bool) ([]byte, error) {
	direction := byte(0)
	if !ascending {
		direction = 1
	}
	content := make([]byte, 37)
	copy(content[:32], headerHash[:])
	content[32] = direction
	binary.LittleEndian.PutUint32(content[33:], 10)

	// Write with context
	if err := WriteMessageWithContext(ctx, stream, content); err != nil {
		return nil, fmt.Errorf("failed to write request: %w", err)
	}

	// Read with context
	response, err := ReadMessageWithContext(ctx, stream)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	fmt.Printf("Received response: %s\n", response.Content)
	return response.Content, nil
}

// BlockRequestMessage represents a request for a sequence of blocks
type BlockRequestMessage struct {
	Hash      crypto.Hash
	Direction byte // 0 for ascending, 1 for descending
	MaxBlocks uint32
}
