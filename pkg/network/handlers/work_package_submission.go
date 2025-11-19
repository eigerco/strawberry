package handlers

import (
	"context"

	"github.com/eigerco/strawberry/internal/crypto/ed25519"

	"fmt"

	"github.com/quic-go/quic-go"

	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/d3l"
	"github.com/eigerco/strawberry/internal/work"
	"github.com/eigerco/strawberry/pkg/serialization/codec/jam"
)

// WorkPackageSubmissionHandler processes incoming CE-133 submission streams
type WorkPackageSubmissionHandler struct {
	// Fetcher is used to retrieve imported segments referenced in the work-package.
	Fetcher d3l.SegmentsFetcher
	// workReportGuarantor handles the rest of the flow after submission:
	// running validation + auth + refinement (CE-134) and distributing guarantees (CE-135).
	workReportGuarantor WorkReportProcessAndGuarantee
	segmentRootLookup   work.SegmentRootLookup
}

// NewWorkPackageSubmissionHandler creates a new handler instance with the given fetcher.
func NewWorkPackageSubmissionHandler(fetcher d3l.SegmentsFetcher, wpSharingHandler WorkReportProcessAndGuarantee, segmentRootLookup work.SegmentRootLookup) *WorkPackageSubmissionHandler {
	return &WorkPackageSubmissionHandler{
		Fetcher:             fetcher,
		workReportGuarantor: wpSharingHandler,
		segmentRootLookup:   segmentRootLookup,
	}
}

// HandleStream processes the CE-133 submission stream from a builder.
// This starts the full flow (CE-133 → CE-134 → CE-135).
// It reads two messages:
//  1. [Core Index (u16) ++ work.Package]
//  2. [Extrinsics (raw bytes)]
//
// Then fetches imported segments (if needed), wraps the data into a bundle,
// and starts validation, refinement, and distribution.
func (h *WorkPackageSubmissionHandler) HandleStream(ctx context.Context, stream quic.Stream, peerKey ed25519.PublicKey) error {
	msg1, err := ReadMessageWithContext(ctx, stream)
	if err != nil {
		return fmt.Errorf("failed to read message 1: %w", err)
	}

	if len(msg1.Content) < 2 {
		return fmt.Errorf("message is too short")
	}

	var coreIndex uint16
	if err = jam.Unmarshal(msg1.Content[:2], &coreIndex); err != nil {
		return fmt.Errorf("failed to unmarshal core index: %w", err)
	}

	var pkg work.Package
	if err = jam.Unmarshal(msg1.Content[2:], &pkg); err != nil {
		return fmt.Errorf("failed to unmarshal work package: %w", err)
	}

	if err = pkg.ValidateSize(); err != nil {
		return fmt.Errorf("failed to validate work package: %w", err)
	}

	msg2, err := ReadMessageWithContext(ctx, stream)
	if err != nil {
		return fmt.Errorf("failed to read extrinsics message: %w", err)
	}
	extrinsics := msg2.Content

	fmt.Printf("received submission with coreIndex=%d, work package with %d work items, extrinsics=%d bytes\n",
		coreIndex, len(pkg.WorkItems), len(extrinsics))

	importedSegments, err := h.fetchAllImportSegments(ctx, pkg)
	if err != nil {
		return err
	}

	builder, err := work.NewPackageBundleBuilder(pkg, h.segmentRootLookup, importedSegments, extrinsics)
	if err != nil {
		return fmt.Errorf("failed to build work package bundle: %w", err)
	}
	bundle, err := builder.Build()
	if err != nil {
		return fmt.Errorf("failed to build work package bundle: %w", err)
	}

	if err = stream.Close(); err != nil {
		return fmt.Errorf("failed to close stream: %w", err)
	}

	return h.workReportGuarantor.ValidateAndProcessWorkPackage(ctx, coreIndex, bundle)
}

func (h *WorkPackageSubmissionHandler) fetchAllImportSegments(ctx context.Context, pkg work.Package) (map[crypto.Hash][]work.Segment, error) {
	// build a map of segment-root to segment indexes dictionary to request multiple segment indexes at a time if necessary
	segmentRootAndIndexes := make(map[crypto.Hash][]uint16)
	for _, item := range pkg.WorkItems {
		for _, imp := range item.ImportedSegments {
			segmentRoot := h.segmentRootLookup.Lookup(imp.Hash)
			segmentRootAndIndexes[segmentRoot] = append(segmentRootAndIndexes[segmentRoot], imp.Index)
		}
	}

	importedSegments := make(map[crypto.Hash][]work.Segment)
	for segmentRoot, indexes := range segmentRootAndIndexes {
		segments, err := h.Fetcher.Fetch(ctx, segmentRoot, indexes...)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch imported segments: %w", err)
		}
		// TODO we should use proofs to verify the consistency of the segments
		// if the segments are inconsistent with the proofs we should fetch again with justifications
		// using protocol 140 and verify the correctness of each response as it is received
		importedSegments[segmentRoot] = segments
	}

	return importedSegments, nil
}

// WorkPackageSubmitter handles outgoing CE-133 submissions (builder side).
type WorkPackageSubmitter struct{}

// SubmitWorkPackage sends a work-package submission to a guarantor over the given stream.
// It sends two messages:
//
//	Message 1: [Core Index (u16) ++ work.Package]
//	Message 2: [Extrinsic data]
func (s *WorkPackageSubmitter) SubmitWorkPackage(ctx context.Context, stream quic.Stream, coreIndex uint16, pkg work.Package, extrinsics []byte) error {
	coreIndexBytes, err := jam.Marshal(coreIndex)
	if err != nil {
		return fmt.Errorf("failed to marshal core index: %w", err)
	}

	pkgBytes, err := jam.Marshal(pkg)
	if err != nil {
		return fmt.Errorf("failed to marshal work package: %w", err)
	}

	// Core Index ++ Work-Package
	msg1 := append(coreIndexBytes, pkgBytes...)
	if err = WriteMessageWithContext(ctx, stream, msg1); err != nil {
		return fmt.Errorf("failed to write message 1: %w", err)
	}

	if err = WriteMessageWithContext(ctx, stream, extrinsics); err != nil {
		return fmt.Errorf("failed to write message 2: %w", err)
	}

	if err = stream.Close(); err != nil {
		return fmt.Errorf("failed to close stream: %w", err)
	}

	return nil
}
