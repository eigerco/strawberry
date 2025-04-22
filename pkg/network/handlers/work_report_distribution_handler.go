package handlers

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"log"

	"github.com/quic-go/quic-go"

	"github.com/eigerco/strawberry/internal/block"
	"github.com/eigerco/strawberry/pkg/serialization/codec/jam"
)

type WorkReportDistributionHandler struct {
}

func NewWorkReportDistributionHandler() *WorkReportDistributionHandler {
	return &WorkReportDistributionHandler{}
}

func (h *WorkReportDistributionHandler) HandleStream(ctx context.Context, stream quic.Stream, peerKey ed25519.PublicKey) error {
	msg, err := ReadMessageWithContext(ctx, stream)
	if err != nil {
		return fmt.Errorf("failed to read guarantee: %w", err)
	}

	var guarantee block.Guarantee
	if err := jam.Unmarshal(msg.Content, &guarantee); err != nil {
		return fmt.Errorf("failed to unmarshal guarantee: %w", err)
	}

	log.Printf("Received work report guarantee with %d signatures", len(guarantee.Credentials))

	if err := stream.Close(); err != nil {
		return fmt.Errorf("failed to close stream: %w", err)
	}

	return nil
}
