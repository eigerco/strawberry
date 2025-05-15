package handlers

import (
	"context"
	"crypto/ed25519"
	"fmt"

	"github.com/quic-go/quic-go"

	"github.com/eigerco/strawberry/internal/block"
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/store"
	"github.com/eigerco/strawberry/pkg/serialization/codec/jam"
)

// WorkReportRequestHandler handles CE-136: inbound work-report requests.
//
// This handler responds to a peer's request for a work-report by its hash.
// If the report is found in the local store, it is sent back in full.
//
// If the report is not found, the stream is closed with an error.
type WorkReportRequestHandler struct {
	store *store.WorkReport
}

func NewWorkReportRequestHandler(store *store.WorkReport) *WorkReportRequestHandler {
	return &WorkReportRequestHandler{store: store}
}

// HandleStream processes an incoming CE-136 Work-Report Request
// This handler assumes that the node has previously stored the requested work report during the guarantee process
func (h *WorkReportRequestHandler) HandleStream(ctx context.Context, stream quic.Stream, peerKey ed25519.PublicKey) error {
	msg, err := ReadMessageWithContext(ctx, stream)
	if err != nil {
		return fmt.Errorf("failed to read message: %w", err)
	}

	if len(msg.Content) != crypto.HashSize {
		return fmt.Errorf("invalid message length: expected %d bytes, got %d", crypto.HashSize, len(msg.Content))
	}

	var hash crypto.Hash
	if err = jam.Unmarshal(msg.Content, &hash); err != nil {
		return fmt.Errorf("failed to unmarshal work-report hash: %w", err)
	}

	wr, err := h.store.GetWorkReport(hash)
	if err != nil {
		return fmt.Errorf("failed to fetch work report: %w", err)
	}

	respBytes, err := jam.Marshal(wr)
	if err != nil {
		return fmt.Errorf("failed to marshal work report: %w", err)
	}

	if err := WriteMessageWithContext(ctx, stream, respBytes); err != nil {
		return fmt.Errorf("failed to write response: %w", err)
	}

	if err := stream.Close(); err != nil {
		return fmt.Errorf("failed to close stream: %w", err)
	}

	return nil
}

// WorkReportRequester handles CE-136: requesting work-reports from peer
//
// # This client-side handler sends a hash to a peer and requests the full work-report
//
// Protocol flow:
// Auditor -> Auditor
//
//	--> Work-Report Hash (32 bytes)
//	--> FIN
//	<-- Work-Report (full, encoded)
//	<-- FIN
//
// This should be used by auditors to request missing work-reports which have been negatively judged by other auditors.
// This protocol is also used when local refinement fails and a node needs to fetch
// the body of the work-report from another peer that has already produced it.
type WorkReportRequester struct {
}

func NewWorkReportRequester() *WorkReportRequester {
	return &WorkReportRequester{}
}

// RequestWorkReport sends a CE-136 request over the given stream to fetch a work-report by its hash
// It marshals the hash, sends it, reads the response, decodes it into a WorkReport, and returns it
//
// If the remote peer cannot fulfill the request, or if an error occurs during transmission, an error is returned
func (r *WorkReportRequester) RequestWorkReport(
	ctx context.Context,
	stream quic.Stream,
	hash crypto.Hash,
) (*block.WorkReport, error) {
	reqBytes, err := jam.Marshal(hash)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal hash: %w", err)
	}

	if err := WriteMessageWithContext(ctx, stream, reqBytes); err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}

	if err := stream.Close(); err != nil {
		return nil, fmt.Errorf("failed to close stream: %w", err)
	}

	respMsg, err := ReadMessageWithContext(ctx, stream)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	var report block.WorkReport
	if err := jam.Unmarshal(respMsg.Content, &report); err != nil {
		return nil, fmt.Errorf("failed to decode work report: %w", err)
	}

	return &report, nil
}
