package handlers

import (
	"context"
	"fmt"
	"slices"

	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/crypto/ed25519"
	"github.com/eigerco/strawberry/internal/validator"
	"github.com/eigerco/strawberry/pkg/network/protocol"
	"github.com/eigerco/strawberry/pkg/serialization/codec/jam"
	"github.com/quic-go/quic-go"
)

// NewSegmentShardRequestJustificationHandler creates a new segment shard request handler
func NewSegmentShardRequestJustificationHandler(validatorSvc validator.ValidatorService) protocol.StreamHandler {
	return &SegmentShardRequestJustificationHandler{
		validatorSvc: validatorSvc,
	}
}

// SegmentShardRequestJustificationHandler handles the incoming CE 140 requests
type SegmentShardRequestJustificationHandler struct {
	validatorSvc validator.ValidatorService
}

// HandleStream handles the incoming CE 140 protocol
// Segment Index = u16
// Justification = [0 ++ Hash OR 1 ++ Hash ++ Hash OR 2 ++ Segment Shard] (Each discriminator is a single byte)
//
// Guarantor -> Assurer
//
// --> [Erasure-Root ++ Shard Index ++ len++[Segment Index]]
// --> FIN
// <-- [Segment Shard]
//
//	for each segment shard {
//	    <-- Justification
//	}
//
// <-- FIN
func (s *SegmentShardRequestJustificationHandler) HandleStream(ctx context.Context, stream *quic.Stream, peerKey ed25519.PublicKey) error {
	requestMsg, err := ReadMessageWithContext(ctx, stream)
	if err != nil {
		return fmt.Errorf("failed to read segment shard request: %w", err)
	}

	req := &ErasureRootShardAndSegmentIndexes{}
	if err := jam.Unmarshal(requestMsg.Content, req); err != nil {
		return fmt.Errorf("failed to decode erasure root shard and segment indexes: %w", err)
	}

	segmentShards, justification, err := s.validatorSvc.SegmentShardRequestJustification(ctx, req.ErasureRoot, req.ShardIndex, req.SegmentIndexes)
	if err != nil {
		return fmt.Errorf("failed to get segment shard request: %w", err)
	}

	if err := WriteMessageWithContext(ctx, stream, slices.Concat(segmentShards...)); err != nil {
		return fmt.Errorf("failed to write segment shard request: %w", err)
	}

	for _, just := range justification {
		justBytes, err := encodeJustification(just)
		if err != nil {
			return err
		}
		if err := WriteMessageWithContext(ctx, stream, justBytes); err != nil {
			return fmt.Errorf("failed to write segment shard request: %w", err)
		}
	}
	if err := stream.Close(); err != nil {
		return fmt.Errorf("failed to close stream: %w", err)
	}
	return nil
}

// SegmentShardRequestJustificationSender CE 140 sender protocol
type SegmentShardRequestJustificationSender struct{}

// SegmentShardRequestJustification implements the sending of the CE 140 protocol, for more details reference SegmentShardRequestHandler
func (s *SegmentShardRequestJustificationSender) SegmentShardRequestJustification(ctx context.Context, stream *quic.Stream, erasureRoot crypto.Hash, shardIndex uint16, segmentIndexes []uint16) (segmentShards [][]byte, justification [][][]byte, err error) {
	bb, err := jam.Marshal(ErasureRootShardAndSegmentIndexes{
		ErasureRoot:    erasureRoot,
		ShardIndex:     shardIndex,
		SegmentIndexes: segmentIndexes,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to encode segment shard request: %w", err)
	}
	if err := WriteMessageWithContext(ctx, stream, bb); err != nil {
		return nil, nil, fmt.Errorf("failed to write segment shard request: %w", err)
	}

	msg, err := ReadMessageWithContext(ctx, stream)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read segment shard request: %w", err)
	}

	segmentShards, err = decodeSegmentShards(msg.Content)
	if err != nil {
		return nil, nil, err
	}

	// expect a justification for each segment shard
	for i := 0; i < len(segmentShards); i++ {
		msgJust, err := ReadMessageWithContext(ctx, stream)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to read segment shard request: %w", err)
		}
		just, err := decodeJustification(msgJust.Content)
		if err != nil {
			return nil, nil, err
		}
		justification = append(justification, just)
	}
	if err := stream.Close(); err != nil {
		return nil, nil, fmt.Errorf("failed to close stream: %w", err)
	}
	return segmentShards, justification, nil
}
