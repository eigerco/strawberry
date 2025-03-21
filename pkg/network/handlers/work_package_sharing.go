package handlers

import (
	"context"
	"fmt"

	"github.com/quic-go/quic-go"

	"github.com/eigerco/strawberry/internal/work"
	"github.com/eigerco/strawberry/pkg/serialization/codec/jam"
)

type ShareToOtherGuarantors func(ctx context.Context, coreIndex uint16, bundle work.PackageBundle) error

type WorkPackageSharer struct {
	shareToOtherGuarantors ShareToOtherGuarantors
}

func NewWorkPackageSharer(shareFunc ShareToOtherGuarantors) *WorkPackageSharer {
	return &WorkPackageSharer{
		shareToOtherGuarantors: shareFunc,
	}
}

// ValidateAndShareWorkPackage sends the work-package bundle to other guarantors.
func (h *WorkPackageSharer) ValidateAndShareWorkPackage(ctx context.Context, coreIndex uint16, bundle work.PackageBundle) error {
	if err := bundle.Package.ValidateLimits(); err != nil {
		return err
	}
	if err := bundle.Package.ValidateGas(); err != nil {
		return err
	}

	// TODO
	// 1. Verify WP authorization
	// 2. Make sure that import segments have been retrieved
	// 3. Run refine in parallel

	return h.shareToOtherGuarantors(ctx, coreIndex, bundle)
}

// SendWorkPackage transmits the work-package bundle to a specific guarantor.
func (h *WorkPackageSharer) SendWorkPackage(
	ctx context.Context,
	stream quic.Stream,
	coreIndex uint16,
	imported []work.ImportedSegment,
	bundle work.PackageBundle,
) error {
	msg1, err := jam.Marshal(struct {
		CoreIndex        uint16
		ImportedSegments []work.ImportedSegment
	}{
		CoreIndex:        coreIndex,
		ImportedSegments: imported,
	})
	if err != nil {
		return fmt.Errorf("failed to marshal first message: %w", err)
	}

	// 1st: “CoreIndex ++ ImportedSegments”
	if err = WriteMessageWithContext(ctx, stream, msg1); err != nil {
		return fmt.Errorf("failed to send first message: %w", err)
	}

	// 2nd: “Work-Package Bundle”
	bundleBytes, err := jam.Marshal(bundle)
	if err != nil {
		return fmt.Errorf("failed to marshal WP bundle: %w", err)
	}
	if err = WriteMessageWithContext(ctx, stream, bundleBytes); err != nil {
		return fmt.Errorf("failed to send WP bundle: %w", err)
	}

	if err = stream.Close(); err != nil {
		return fmt.Errorf("failed to close stream: %w", err)
	}

	return nil
}
