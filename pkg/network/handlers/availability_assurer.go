package handlers

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"slices"

	"github.com/quic-go/quic-go"

	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/validator"
	"github.com/eigerco/strawberry/pkg/serialization/codec/jam"
)

type StreamHandlerFunc func(ctx context.Context, stream quic.Stream, peerKey ed25519.PublicKey) error

func (fn StreamHandlerFunc) HandleStream(ctx context.Context, stream quic.Stream, peerKey ed25519.PublicKey) error {
	return fn(ctx, stream, peerKey)
}

type ErasureRootAndShardIndex struct {
	ErasureRoot crypto.Hash
	ShardIndex  uint16
}

// ShardDistHandler handles protocol CE 137, decodes the erasure rood and shard index
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
func ShardDistHandler(validatorSvc validator.ValidatorService) StreamHandlerFunc {
	return func(ctx context.Context, stream quic.Stream, peerKey ed25519.PublicKey) error {
		defer stream.Close()

		msg, err := ReadMessageWithContext(ctx, stream)
		if err != nil {
			return fmt.Errorf("unable to read message %w", err)
		}

		req := &ErasureRootAndShardIndex{}
		if err := jam.Unmarshal(msg.Content, req); err != nil {
			return fmt.Errorf("unable to decode message: %w", err)
		}

		bundleShard, segmentShards, justification, err := validatorSvc.ShardDist(ctx, req.ErasureRoot, req.ShardIndex)
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
		return nil
	}
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
			return nil, fmt.Errorf("unexpected justification path value (should be eiter one ore two hashes): %v", len(just))
		}
	}
	return justificationBytes, nil
}

func decodeJustification(justificationBytes []byte) (justification [][]byte, err error) {
	for i := 0; i < len(justificationBytes); {
		skip := 0
		switch justificationBytes[i] {
		case 0:
			skip = 33
		case 1:
			skip = 65
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

// CallShardDist implements the sender side of the CE 137 protocol for more details check ShardDistHandler
func CallShardDist(stream quic.Stream, ctx context.Context, erasureRoot crypto.Hash, shardIndex uint16) (bundleShard []byte, segmentShard [][]byte, justification [][]byte, err error) {
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

	if len(segmentShardMsg.Content)%12 != 0 {
		return nil, nil, nil, fmt.Errorf("invalid segment shard length (%d): %w", len(segmentShardMsg.Content), err)
	}
	for i := 0; i < len(segmentShardMsg.Content); i += 12 {
		segmentShard = append(segmentShard, segmentShardMsg.Content[i:i+12])
	}
	justificationMsg, err := ReadMessageWithContext(ctx, stream)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to read justification message: %w", err)
	}
	justification, err = decodeJustification(justificationMsg.Content)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to decode justification: %w", err)
	}
	return bundleShardMsg.Content, segmentShard, justification, nil
}
