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

// WorkReportDistributionHandler processes incoming CE-135 streams
// This handler is used by a validator who receives a work-report guarantee
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

	// TODO: proceed with basic validation (signatures) and proceed to block authoring if valid

	return nil
}

type WorkReportDistributionSender struct{}

func NewWorkReportDistributionSender() *WorkReportDistributionSender {
	return &WorkReportDistributionSender{}
}

// SendGuarantee handles CE-135 and sends guaranteed work report to validator
//
// Guaranteed Work-Report = Work-Report ++ Slot ++ len++[Validator Index ++ Ed25519 Signature] (As in GP)
//
// Guarantor -> Validator
//
// --> Guaranteed Work-Report
// --> FIN
// <-- FIN
func (s *WorkReportDistributionSender) SendGuarantee(
	ctx context.Context,
	stream quic.Stream,
	validatorIndex uint16,
	guaranteeData []byte,
) error {
	if err := WriteMessageWithContext(ctx, stream, guaranteeData); err != nil {
		return fmt.Errorf("failed to send guarantee to validator %v: %w", validatorIndex, err)
	}

	err := stream.Close()
	if err != nil {
		return fmt.Errorf("failed to close stream to validator %v: %w", validatorIndex, err)
	}

	return nil
}
