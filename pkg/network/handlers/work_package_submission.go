package handlers

import (
	"context"
	"crypto/ed25519"
	"fmt"

	"github.com/quic-go/quic-go"

	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/work"
	"github.com/eigerco/strawberry/pkg/serialization/codec/jam"
)

// ImportedSegmentsFetcher defines an interface for fetching imported segments from the availability system
type ImportedSegmentsFetcher interface {
	FetchImportedSegment(hash crypto.Hash) ([]byte, error)
}

// ImportSegments implements ImportedSegmentsFetcher
type ImportSegments struct{}

func (m *ImportSegments) FetchImportedSegment(hash crypto.Hash) ([]byte, error) {
	fmt.Printf("fetching imported segment for hash %x\n", hash)
	// TODO implement

	return []byte{}, nil
}

// WorkPackageSubmissionHandler processes incoming CE-133 submission streams
type WorkPackageSubmissionHandler struct {
	Fetcher          ImportedSegmentsFetcher
	WPSharingHandler *WorkPackageSharer
}

// NewWorkPackageSubmissionHandler creates a new handler instance with the given fetcher.
func NewWorkPackageSubmissionHandler(fetcher ImportedSegmentsFetcher, wpSharingHandler *WorkPackageSharer) *WorkPackageSubmissionHandler {
	return &WorkPackageSubmissionHandler{
		Fetcher:          fetcher,
		WPSharingHandler: wpSharingHandler,
	}
}

// HandleStream implements the guarantor side of the CE-133 protocol.
// It expects two messages:
//
//	Message 1: [Core Index (u16) ++ work.Package]
//	Message 2: [Extrinsic data (raw bytes)]
//
// After reading these it should fetch imported segments from the availability system
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

	for _, item := range pkg.WorkItems {
		for _, imp := range item.ImportedSegments {
			_, err = h.Fetcher.FetchImportedSegment(imp.Hash)
			if err != nil {
				// retry or reject package
				continue
			}
			// Process or store segment data
		}
	}

	bundle := work.PackageBundle{
		Package:    pkg,
		Extrinsics: extrinsics,
	}

	if err = stream.Close(); err != nil {
		return fmt.Errorf("failed to close stream: %w", err)
	}

	return h.WPSharingHandler.ValidateAndShareWorkPackage(ctx, coreIndex, bundle)
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
