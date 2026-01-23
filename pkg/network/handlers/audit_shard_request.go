package handlers

import (
	"context"
	"fmt"

	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/crypto/ed25519"
	"github.com/eigerco/strawberry/internal/validator"
	"github.com/eigerco/strawberry/pkg/network/protocol"
	"github.com/eigerco/strawberry/pkg/serialization/codec/jam"
	"github.com/quic-go/quic-go"
)

// NewAuditShardRequestHandler creates a new AuditShardRequestHandler
func NewAuditShardRequestHandler(validatorSvc validator.ValidatorService) protocol.StreamHandler {
	return &AuditShardRequestHandler{
		validatorSvc: validatorSvc,
	}
}

// AuditShardRequestHandler handles the receiving part of the CE 138 protocol
type AuditShardRequestHandler struct {
	validatorSvc validator.ValidatorService
}

// HandleStream handles the incoming CE 138 protocol
// Justification = [0 ++ Hash OR 1 ++ Hash ++ Hash] (Each discriminator is a single byte)
//
// Auditor -> Assurer
//
// --> Erasure-Root ++ Shard Index
// --> FIN
// <-- Bundle Shard
// <-- Justification
// <-- FIN
func (h *AuditShardRequestHandler) HandleStream(ctx context.Context, stream *quic.Stream, peerKey ed25519.PublicKey) error {
	msg, err := ReadMessageWithContext(ctx, stream)
	if err != nil {
		return fmt.Errorf("unable to read message %w", err)
	}
	req := ErasureRootAndShardIndex{}
	if err := jam.Unmarshal(msg.Content, &req); err != nil {
		return fmt.Errorf("unable to decode erasure root and shard index %w", err)
	}

	bundleShard, justification, err := h.validatorSvc.AuditShardRequest(ctx, req.ErasureRoot, req.ShardIndex)
	if err != nil {
		return fmt.Errorf("unable get the shard with index=%v: %w", req.ShardIndex, err)
	}
	if err := WriteMessageWithContext(ctx, stream, bundleShard); err != nil {
		return fmt.Errorf("unable to write message: %w", err)
	}

	justBytes, err := encodeJustification(justification)
	if err != nil {
		return fmt.Errorf("unable to encode justification: %w", err)
	}
	if err := WriteMessageWithContext(ctx, stream, justBytes); err != nil {
		return fmt.Errorf("unable to write message: %w", err)
	}

	if err := stream.Close(); err != nil {
		return fmt.Errorf("unable to close stream: %w", err)
	}

	return nil
}

type AuditShardRequestSender struct{}

// AuditShardRequest implements the sender side of the CE 138 protocol for more details see AuditShardRequestHandler
func (s *AuditShardRequestSender) AuditShardRequest(ctx context.Context, stream *quic.Stream, erasureRoot crypto.Hash, shardIndex uint16) (bundleShard []byte, justification [][]byte, err error) {
	reqBytes, err := jam.Marshal(ErasureRootAndShardIndex{
		ErasureRoot: erasureRoot,
		ShardIndex:  shardIndex,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("unable to marshal erasure root and shard index: %w", err)
	}
	if err := WriteMessageWithContext(ctx, stream, reqBytes); err != nil {
		return nil, nil, fmt.Errorf("unable to write message: %w", err)
	}

	bundleShardMsg, err := ReadMessageWithContext(ctx, stream)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to read bundle shard message: %w", err)
	}
	justificationMsg, err := ReadMessageWithContext(ctx, stream)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to read justification message: %w", err)
	}
	justification, err = decodeJustification(justificationMsg.Content)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to decode justification: %w", err)
	}
	if err := stream.Close(); err != nil {
		return nil, nil, fmt.Errorf("unable to close stream: %w", err)
	}
	return bundleShardMsg.Content, justification, nil
}
