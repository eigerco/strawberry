package handlers

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"github.com/eigerco/strawberry/internal/validator"
	"log"
	"sync"

	"github.com/quic-go/quic-go"

	"github.com/eigerco/strawberry/internal/authorization"
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/refine"
	"github.com/eigerco/strawberry/internal/service"
	"github.com/eigerco/strawberry/internal/store"
	"github.com/eigerco/strawberry/internal/work"
	"github.com/eigerco/strawberry/internal/work/results"
	"github.com/eigerco/strawberry/pkg/network/peer"
	"github.com/eigerco/strawberry/pkg/network/protocol"
	"github.com/eigerco/strawberry/pkg/serialization/codec/jam"
)

// WorkPackageSharingHandler processes incoming CE-134 streams
// This handler is used by a guarantor who receives a work-package bundle from another guarantor.
type WorkPackageSharingHandler struct {
	mu                  sync.RWMutex
	currentAssignedCore uint16
	privateKey          ed25519.PrivateKey
	auth                authorization.AuthPVMInvoker
	refine              refine.RefinePVMInvoker
	serviceState        service.ServiceState
	store               *store.WorkReport
	validatorService    validator.ValidatorService
}

// WorkPackageSharingResponse is the response payload of CE-134
// <-- Work-Report Hash ++ Ed25519 Signature
type WorkPackageSharingResponse struct {
	WorkReportHash crypto.Hash
	Signature      crypto.Ed25519Signature
}

// NewWorkPackageSharingHandler creates a new WorkPackageSharingHandler instance.
func NewWorkPackageSharingHandler(
	auth authorization.AuthPVMInvoker,
	refine refine.RefinePVMInvoker,
	privateKey ed25519.PrivateKey,
	serviceState service.ServiceState,
	store *store.WorkReport,
	validatorService validator.ValidatorService,
) *WorkPackageSharingHandler {
	return &WorkPackageSharingHandler{
		privateKey:       privateKey,
		auth:             auth,
		refine:           refine,
		serviceState:     serviceState,
		store:            store,
		validatorService: validatorService,
	}
}

func (h *WorkPackageSharingHandler) SetCurrentCore(core uint16) {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.currentAssignedCore = core
}

// HandleStream implements the guarantor side of the CE-134 protocol.
// It reads two messages:
//  1. [Core Index ++ Segments-Root Mappings]
//  2. [Work-Package Bundle]
//
// [Work-Report Hash ++ Ed25519 Signature].
func (h *WorkPackageSharingHandler) HandleStream(ctx context.Context, stream quic.Stream, peerKey ed25519.PublicKey) error {
	// Read Core Index and Segments-Root Mappings
	msg1, err := ReadMessageWithContext(ctx, stream)
	if err != nil {
		return fmt.Errorf("failed to read first message: %w", err)
	}

	var coreIndex uint16
	if err = jam.Unmarshal(msg1.Content[:2], &coreIndex); err != nil {
		return fmt.Errorf("failed to unmarshal share header: %w", err)
	}

	h.mu.RLock()
	assigned := h.currentAssignedCore
	h.mu.RUnlock()

	if assigned != coreIndex {
		return fmt.Errorf("not assigned to core %d, the current node core %d", coreIndex, assigned)
	}

	var rootMappings []SegmentRootMapping
	if err = jam.Unmarshal(msg1.Content[2:], &rootMappings); err != nil {
		return fmt.Errorf("failed to unmarshal work package: %w", err)
	}

	// Read the work-package bundle
	msg2, err := ReadMessageWithContext(ctx, stream)
	if err != nil {
		return fmt.Errorf("failed to read work package bundle: %w", err)
	}

	bundle := &work.PackageBundle{}
	if err := jam.Unmarshal(msg2.Content, bundle); err != nil {
		return fmt.Errorf("failed to unmarshal work package bundle: %w", err)
	}

	log.Printf("Received work package bundle with %d work item(s)", len(bundle.Package().WorkItems))

	segmentRootLookup := buildSegmentRootLookup(rootMappings)

	authOutput, err := h.auth.InvokePVM(bundle.Package(), coreIndex)
	if err != nil {
		return fmt.Errorf("authorization failed: %w", err)
	}

	shards, workReport, err := results.ProduceWorkReport(h.refine, h.serviceState, authOutput, coreIndex, bundle, segmentRootLookup)
	if err != nil {
		return fmt.Errorf("failed to produce work report: %w", err)
	}

	if err := h.validatorService.StoreAllShards(ctx, workReport.WorkPackageSpecification.ErasureRoot, shards.Bundle, shards.Segments, shards.BundleHashAndSegmentsRoot); err != nil {
		return fmt.Errorf("failed to store shards: %w", err)
	}

	err = h.store.PutWorkReport(workReport)
	if err != nil {
		return fmt.Errorf("failed to store work report: %w", err)
	}

	workReportHash, err := workReport.Hash()
	if err != nil {
		return fmt.Errorf("failed to hash work report: %w", err)
	}

	signature := ed25519.Sign(h.privateKey, workReportHash[:])

	resp := WorkPackageSharingResponse{
		WorkReportHash: workReportHash,
		Signature:      crypto.Ed25519Signature(signature),
	}
	respBytes, err := jam.Marshal(resp)
	if err != nil {
		return fmt.Errorf("failed to marshal response: %w", err)
	}

	if err := WriteMessageWithContext(ctx, stream, respBytes); err != nil {
		return fmt.Errorf("failed to write response: %w", err)
	}

	if err := stream.Close(); err != nil {
		return fmt.Errorf("failed to close stream: %w", err)
	}

	log.Printf("CE-134: Sent work-report hash and signature successfully")

	return nil
}

type WorkPackageSharingRequester struct{}

func NewWorkPackageSharingRequester() *WorkPackageSharingRequester {
	return &WorkPackageSharingRequester{}
}

// SendRequest hands CE 134 sends 2 messages to another guarantor and closes the stream :
//
// --> Core Index ++ Segments-Root Mappings
//   - Informs the receiving guarantor which core this work-package belongs to.
//   - Provides the mapping between imported segment hashes and their Merkle roots.
//   - This mapping is used during refinement to validate imported segments.
//
// --> Work-Package Bundle
//   - Contains the actual work-package bundle and any associated extrinsics.
//
// --> FIN
//   - Closes the stream after sending both messages. The response is expected before finalization.
//
// <-- Work-Report Hash ++ Ed25519 Signature
//   - The receiving guarantor performs refinement and responds with:
//   - The hash of the resulting work-report.
//   - Their Ed25519 signature over the hash.
//   - This response is used to help assemble a guaranteed work-report.
//
// <-- FIN
//   - The stream is closed after the response is read and decoded.
//
// Returns:
// - A `workPackageSharingResponse` containing the signed hash of the refined work-report.
// - An error if sending, receiving, decoding, or stream closure fails.
func (r *WorkPackageSharingRequester) SendRequest(
	ctx context.Context,
	g *peer.Peer,
	coreIndex uint16,
	imported []SegmentRootMapping,
	bundleBytes []byte,
) (*WorkPackageSharingResponse, error) {
	msg1, err := jam.Marshal(struct {
		CoreIndex          uint16
		SegmentRootMapping []SegmentRootMapping
	}{
		CoreIndex:          coreIndex,
		SegmentRootMapping: imported,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to marshal first message: %w", err)
	}

	stream, err := g.ProtoConn.OpenStream(ctx, protocol.StreamKindWorkPackageShare)
	if err != nil {
		return nil, fmt.Errorf("failed to open stream: %v", err)
	}

	// 1st: “CoreIndex ++ Segments-Root Mappings”
	if err = WriteMessageWithContext(ctx, stream, msg1); err != nil {
		return nil, fmt.Errorf("failed to send first message: %w", err)
	}

	// 2nd: “Work-Package Bundle”
	if err = WriteMessageWithContext(ctx, stream, bundleBytes); err != nil {
		return nil, fmt.Errorf("failed to send WP bundle: %w", err)
	}

	if err := stream.Close(); err != nil {
		return nil, fmt.Errorf("failed to close stream: %w", err)
	}

	// Handle CE-134 response from the receiving guarantor
	msg, err := ReadMessageWithContext(ctx, stream)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	var response WorkPackageSharingResponse
	if err := jam.Unmarshal(msg.Content, &response); err != nil {
		return nil, fmt.Errorf("failed to decode CE-134 response: %w", err)
	}

	return &response, nil
}

func buildSegmentRootLookup(mappings []SegmentRootMapping) work.SegmentRootLookup {
	lookup := make(map[crypto.Hash]crypto.Hash)
	for _, m := range mappings {
		lookup[m.WorkPackageHash] = m.SegmentRoot
	}
	return lookup
}
