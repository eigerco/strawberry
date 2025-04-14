package handlers

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"github.com/eigerco/strawberry/pkg/network/protocol"
	"slices"

	"github.com/quic-go/quic-go"

	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/validator"
	"github.com/eigerco/strawberry/pkg/serialization/codec/jam"
)

const SegmentShardLength = 12

// NewShardDistributionHandler creates a new ShardDistributionHandler
func NewShardDistributionHandler(validatorSvc validator.ValidatorService) protocol.StreamHandler {
	return &ShardDistributionHandler{
		validatorSvc: validatorSvc,
	}
}

// ShardDistributionHandler processes incoming CE-137 submission streams
type ShardDistributionHandler struct {
	validatorSvc validator.ValidatorService
}

type ErasureRootAndShardIndex struct {
	ErasureRoot crypto.Hash
	ShardIndex  uint16
}

// HandleStream handles protocol CE 137, decodes the erasure root and shard index
// requests the shards and justification from the validator service
// encodes and returns the respective shards and justification
//
// Justification = [0 ++ Hash OR 1 ++ Hash ++ Hash] (Each discriminator is a single byte)
//
// Assurer -> Guarantor
//
// --> Erasure-Root ++ Shard Index
// --> FIN
// <-- Bundle Shard
// <-- [Segment Shard] (Should include all exported and proof segment shards with the given index)
// <-- Justification
// <-- FIN
func (h *ShardDistributionHandler) HandleStream(ctx context.Context, stream quic.Stream, peerKey ed25519.PublicKey) error {
	msg, err := ReadMessageWithContext(ctx, stream)
	if err != nil {
		return fmt.Errorf("unable to read message %w", err)
	}

	req := &ErasureRootAndShardIndex{}
	if err := jam.Unmarshal(msg.Content, req); err != nil {
		return fmt.Errorf("unable to decode message: %w", err)
	}

	bundleShard, segmentShards, justification, err := h.validatorSvc.ShardDistribution(ctx, req.ErasureRoot, req.ShardIndex)
	if err != nil {
		return fmt.Errorf("unable get the shard with index=%v: %w", req.ShardIndex, err)
	}

	if err := WriteMessageWithContext(ctx, stream, bundleShard); err != nil {
		return fmt.Errorf("unable to write message: %w", err)
	}

	if err := WriteMessageWithContext(ctx, stream, slices.Concat(segmentShards...)); err != nil {
		return fmt.Errorf("unable to write message: %w", err)
	}

	justBytes, err := encodeJustification(justification)
	if err != nil {
		return fmt.Errorf("unable to encode justification: %w", err)
	}
	if err := WriteMessageWithContext(ctx, stream, justBytes); err != nil {
		return fmt.Errorf("unable to write message: %w", err)
	}
	if err = stream.Close(); err != nil {
		return fmt.Errorf("failed to close stream: %w", err)
	}
	return nil
}

func encodeJustification(justification [][]byte) (justificationBytes []byte, err error) {
	for _, just := range justification {
		switch len(just) {
		case 32: // one hash
			justificationBytes = append(justificationBytes, 0)
			justificationBytes = append(justificationBytes, just...)
		case 64: // two hashes in case of a leaf
			justificationBytes = append(justificationBytes, 1)
			justificationBytes = append(justificationBytes, just...)
		default:
			return nil, fmt.Errorf("unexpected justification path value (should be either one or two hashes): %v", len(just))
		}
	}
	return justificationBytes, nil
}

func decodeJustification(justificationBytes []byte) (justification [][]byte, err error) {
	for i := 0; i < len(justificationBytes); {
		skip := 0
		switch justificationBytes[i] {
		case 0:
			skip = crypto.HashSize + 1
		case 1:
			skip = crypto.HashSize*2 + 1
		default:
			return nil, fmt.Errorf("unexpected justification path segment format")
		}
		if i+skip > len(justificationBytes) {
			return nil, fmt.Errorf("unexpected justification path segment length")
		}
		justification = append(justification, justificationBytes[i+1:i+skip])
		i += skip
	}

	return justification, nil
}

// ShardDistributionSender handles outgoing CE-137 calls
type ShardDistributionSender struct{}

// ShardDistribution implements the sender side of the CE 137 protocol for more details check ShardDistributionHandler
func (s *ShardDistributionSender) ShardDistribution(ctx context.Context, stream quic.Stream, erasureRoot crypto.Hash, shardIndex uint16) (bundleShard []byte, segmentShard [][]byte, justification [][]byte, err error) {
	messageBytes, err := jam.Marshal(ErasureRootAndShardIndex{ErasureRoot: erasureRoot, ShardIndex: shardIndex})
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to encode erasure root and shard index: %w", err)
	}
	if err := WriteMessageWithContext(ctx, stream, messageBytes); err != nil {
		return nil, nil, nil, fmt.Errorf("failed to write erasure root and shard index: %w", err)
	}
	bundleShardMsg, err := ReadMessageWithContext(ctx, stream)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to read bundle shard message: %w", err)
	}
	segmentShardMsg, err := ReadMessageWithContext(ctx, stream)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to read segment shard message: %w", err)
	}

	if len(segmentShardMsg.Content)%SegmentShardLength != 0 {
		return nil, nil, nil, fmt.Errorf("invalid segment shard length (%d)", len(segmentShardMsg.Content))
	}
	for i := 0; i < len(segmentShardMsg.Content); i += SegmentShardLength {
		segmentShard = append(segmentShard, segmentShardMsg.Content[i:i+SegmentShardLength])
	}
	justificationMsg, err := ReadMessageWithContext(ctx, stream)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to read justification message: %w", err)
	}
	justification, err = decodeJustification(justificationMsg.Content)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to decode justification: %w", err)
	}
	if err = stream.Close(); err != nil {
		return nil, nil, nil, fmt.Errorf("failed to close stream: %w", err)
	}
	return bundleShardMsg.Content, segmentShard, justification, nil
}
