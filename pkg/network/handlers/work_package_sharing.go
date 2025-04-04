package handlers

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sync"

	"github.com/quic-go/quic-go"

	"github.com/eigerco/strawberry/internal/common"
	"github.com/eigerco/strawberry/internal/work"
	"github.com/eigerco/strawberry/pkg/network/peer"
	"github.com/eigerco/strawberry/pkg/network/protocol"
	"github.com/eigerco/strawberry/pkg/serialization/codec/jam"
)

type WorkPackageSharer struct {
	guarantors []*peer.Peer
}

func NewWorkPackageSharer() *WorkPackageSharer {
	return &WorkPackageSharer{}
}

func (h *WorkPackageSharer) SetGuarantors(guarantors []*peer.Peer) {
	h.guarantors = guarantors
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

	return h.shareWorkPackageWithOtherGuarantors(ctx, coreIndex, bundle)
}

func (h *WorkPackageSharer) shareWorkPackageWithOtherGuarantors(ctx context.Context, coreIndex uint16, bundle work.PackageBundle) error {
	if coreIndex >= common.TotalNumberOfCores {
		return fmt.Errorf("invalid coreIndex: %d (must be < %d)",
			coreIndex, common.TotalNumberOfCores)
	}

	if h.guarantors == nil {
		return errors.New("no guarantors set")
	}

	var wg sync.WaitGroup
	for _, g := range h.guarantors {
		wg.Add(1)
		go func(g *peer.Peer) {
			defer wg.Done()

			stream, err := g.ProtoConn.OpenStream(ctx, protocol.StreamKindWorkPackageShare)
			if err != nil {
				log.Printf("Failed to open stream to peer %v: %v", g, err)
				return
			}

			err = h.sendWorkPackage(ctx, stream, coreIndex, []work.ImportedSegment{}, bundle)
			if err != nil {
				log.Printf("Failed to share WP with peer %v: %v", g, err)
			}

			// TODO:  Once the receive side (CE-134 response) is implemented we should read the response
		}(g)
	}

	wg.Wait()

	return nil
}

// SendWorkPackage transmits the work-package bundle to a specific guarantor.
func (h *WorkPackageSharer) sendWorkPackage(
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
