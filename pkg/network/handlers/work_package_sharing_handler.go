package handlers

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"log"

	"github.com/quic-go/quic-go"

	"github.com/eigerco/strawberry/internal/authorization"
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/refine"
	"github.com/eigerco/strawberry/internal/service"
	"github.com/eigerco/strawberry/internal/work"
	"github.com/eigerco/strawberry/pkg/serialization/codec/jam"
)

// WorkPackageSharingHandler processes incoming CE-134 streams
// This handler is used by a guarantor who receives a work-package bundle from another guarantor.
type WorkPackageSharingHandler struct {
	privateKey   ed25519.PrivateKey
	Auth         authorization.AuthPVMInvoker
	Refine       refine.RefinePVMInvoker
	ServiceState service.ServiceState
}

// NewWorkPackageSharingHandler creates a new WorkPackageSharingHandler instance.
func NewWorkPackageSharingHandler(
	auth authorization.AuthPVMInvoker,
	refine refine.RefinePVMInvoker,
	privateKey ed25519.PrivateKey,
	serviceState service.ServiceState,
) *WorkPackageSharingHandler {
	return &WorkPackageSharingHandler{
		privateKey:   privateKey,
		Auth:         auth,
		Refine:       refine,
		ServiceState: serviceState,
	}
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

	var rootMappings []SegmentRootMapping
	if err = jam.Unmarshal(msg1.Content[2:], &rootMappings); err != nil {
		return fmt.Errorf("failed to unmarshal work package: %w", err)
	}

	// Read the work-package bundle
	msg2, err := ReadMessageWithContext(ctx, stream)
	if err != nil {
		return fmt.Errorf("failed to read work package bundle: %w", err)
	}

	var bundle work.PackageBundle
	if err := jam.Unmarshal(msg2.Content, &bundle); err != nil {
		return fmt.Errorf("failed to unmarshal work package bundle: %w", err)
	}

	log.Printf("Received work package bundle with %d work item(s) and %d extrinsic byte(s)",
		len(bundle.Package.WorkItems), len(bundle.Extrinsics))

	segmentRootLookup := buildSegmentRootLookup(rootMappings)

	if err := h.verifySegmentRootMappings(segmentRootLookup, bundle); err != nil {
		return fmt.Errorf("mappings verification failed: %w", err)
	}

	authOutput, err := h.Auth.InvokePVM(bundle.Package, coreIndex)
	if err != nil {
		return fmt.Errorf("authorization failed: %w", err)
	}

	workReport, err := ProduceWorkReport(ctx, h.Refine, h.ServiceState, authOutput, coreIndex, bundle, segmentRootLookup)
	if err != nil {
		return fmt.Errorf("failed to produce work report: %w", err)
	}

	workReportHash, err := workReport.Hash()
	if err != nil {
		return fmt.Errorf("failed to hash work report: %w", err)
	}

	signature := ed25519.Sign(h.privateKey, workReportHash[:])

	// Prepare the response: Work-Report Hash ++ Ed25519 Signature.
	response := struct {
		WorkReportHash crypto.Hash
		Signature      []byte
	}{
		WorkReportHash: workReportHash,
		Signature:      signature,
	}

	respBytes, err := jam.Marshal(response)
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

func buildSegmentRootLookup(mappings []SegmentRootMapping) map[crypto.Hash]crypto.Hash {
	lookup := make(map[crypto.Hash]crypto.Hash)
	for _, m := range mappings {
		lookup[m.WorkPackageHash] = m.SegmentRoot
	}
	return lookup
}

// simple verification (wp hash -> segment root)
func (h *WorkPackageSharingHandler) verifySegmentRootMappings(lookup map[crypto.Hash]crypto.Hash, bundle work.PackageBundle) error {
	for _, item := range bundle.Package.WorkItems {
		for _, imp := range item.ImportedSegments {
			if _, exists := lookup[imp.Hash]; !exists {
				log.Printf("Missing mapping for imported segment hash %x", imp.Hash)
				return fmt.Errorf("missing segment-root mapping for hash: %x", imp.Hash)
			}
		}
	}

	log.Print("Segment-root mappings verified")

	return nil
}
