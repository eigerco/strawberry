package handlers

import (
	"context"

	"github.com/eigerco/strawberry/internal/crypto/ed25519"

	"fmt"
	"slices"

	"github.com/quic-go/quic-go"

	"github.com/eigerco/strawberry/internal/common"
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/validator"
	"github.com/eigerco/strawberry/pkg/network/protocol"
	"github.com/eigerco/strawberry/pkg/serialization/codec/jam"
)

// NewSegmentShardRequestHandler creates a new segment shard request handler
func NewSegmentShardRequestHandler(validatorSvc validator.ValidatorService) protocol.StreamHandler {
	return &SegmentShardRequestHandler{
		validatorSvc: validatorSvc,
	}
}

// SegmentShardRequestHandler handles the incoming CE 139 requests
type SegmentShardRequestHandler struct {
	validatorSvc validator.ValidatorService
}

type ErasureRootShardAndSegmentIndexes struct {
	ErasureRoot    crypto.Hash
	ShardIndex     uint16
	SegmentIndexes []uint16
}

// HandleStream handles the incoming CE 139 protocol
// Segment Index = u16
//
// Guarantor -> Assurer
//
// --> [Erasure-Root ++ Shard Index ++ len++[Segment Index]]
// --> FIN
// <-- [Segment Shard]
// <-- FIN
func (s *SegmentShardRequestHandler) HandleStream(ctx context.Context, stream quic.Stream, peerKey ed25519.PublicKey) error {
	requestMsg, err := ReadMessageWithContext(ctx, stream)
	if err != nil {
		return fmt.Errorf("failed to read segment shard request: %w", err)
	}

	req := &ErasureRootShardAndSegmentIndexes{}
	if err := jam.Unmarshal(requestMsg.Content, req); err != nil {
		return fmt.Errorf("failed to decode erasure root shard and segment indexes: %w", err)
	}
	if len(req.SegmentIndexes) > 2*common.MaxNrImportsExports {
		return fmt.Errorf("requested number of segment shards is too high")
	}

	segmentShards, err := s.validatorSvc.SegmentShardRequest(ctx, req.ErasureRoot, req.ShardIndex, req.SegmentIndexes)
	if err != nil {
		return fmt.Errorf("failed to get segment shard request: %w", err)
	}

	if err := WriteMessageWithContext(ctx, stream, slices.Concat(segmentShards...)); err != nil {
		return fmt.Errorf("failed to write segment shard request: %w", err)
	}

	if err := stream.Close(); err != nil {
		return fmt.Errorf("failed to close stream: %w", err)
	}
	return nil
}

// SegmentShardRequestSender CE 139 sender protocol
type SegmentShardRequestSender struct{}

// SegmentShardRequest implements the sending of the CE 139 protocol, for more details reference SegmentShardRequestHandler
func (s *SegmentShardRequestSender) SegmentShardRequest(ctx context.Context, stream quic.Stream, erasureRoot crypto.Hash, shardIndex uint16, segmentIndexes []uint16) (segmentShards [][]byte, err error) {
	bb, err := jam.Marshal(ErasureRootShardAndSegmentIndexes{
		ErasureRoot:    erasureRoot,
		ShardIndex:     shardIndex,
		SegmentIndexes: segmentIndexes,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to encode segment shard request: %w", err)
	}
	if err := WriteMessageWithContext(ctx, stream, bb); err != nil {
		return nil, fmt.Errorf("failed to write segment shard request: %w", err)
	}

	if err := stream.Close(); err != nil {
		return nil, fmt.Errorf("failed to close stream: %w", err)
	}

	msg, err := ReadMessageWithContext(ctx, stream)
	if err != nil {
		return nil, fmt.Errorf("failed to read segment shard request: %w", err)
	}

	segmentShards, err = decodeSegmentShards(msg.Content)
	if err != nil {
		return nil, err
	}
	return segmentShards, nil
}
