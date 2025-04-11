package handlers

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sync"

	"github.com/quic-go/quic-go"

	"github.com/eigerco/strawberry/internal/authorization"
	"github.com/eigerco/strawberry/internal/common"
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/refine"
	"github.com/eigerco/strawberry/internal/service"
	"github.com/eigerco/strawberry/internal/work"
	"github.com/eigerco/strawberry/pkg/network/peer"
	"github.com/eigerco/strawberry/pkg/network/protocol"
	"github.com/eigerco/strawberry/pkg/serialization/codec/jam"
)

type WorkPackageSharer struct {
	guarantors   []*peer.Peer
	auth         authorization.AuthPVMInvoker
	refine       refine.RefinePVMInvoker
	serviceState service.ServiceState
}

// SegmentRootMapping It maps a work-package hash (h⊞) to the actual segment root (H).
type SegmentRootMapping struct {
	WorkPackageHash crypto.Hash // h⊞
	SegmentRoot     crypto.Hash // H
}

func NewWorkPackageSharer(
	auth authorization.AuthPVMInvoker,
	refine refine.RefinePVMInvoker,
	serviceState service.ServiceState,
) *WorkPackageSharer {
	return &WorkPackageSharer{auth: auth, refine: refine, serviceState: serviceState}
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
	if err := bundle.Package.ValidateSize(); err != nil {
		return err
	}

	authOutput, err := h.auth.InvokePVM(bundle.Package, coreIndex)
	if err != nil {
		return fmt.Errorf("authorization failed: %w", err)
	}
	// TODO retrieve import segments and produce the mappings
	segments := h.buildSegmentRootMapping(bundle)

	return h.shareWorkPackageAndRefine(ctx, authOutput, segments, coreIndex, bundle)
}

func (h *WorkPackageSharer) shareWorkPackageAndRefine(
	ctx context.Context,
	authOutput []byte,
	segments []SegmentRootMapping,
	coreIndex uint16,
	bundle work.PackageBundle,
) error {
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

			defer func() {
				if err = stream.Close(); err != nil {
					fmt.Printf("failed to close stream: %v", err)
				}
			}()

			err = h.sendWorkPackage(ctx, stream, coreIndex, segments, bundle)
			if err != nil {
				log.Printf("Failed to share WP with peer %v: %v", g, err)
			}

			// Handle CE-134 response from the receiving guarantor
			msg, err := ReadMessageWithContext(ctx, stream)
			if err != nil {
				log.Printf("Failed to read response from peer %v: %v", g, err)
				return
			}

			var response struct {
				WorkReportHash crypto.Hash
				Signature      []byte
			}
			if err := jam.Unmarshal(msg.Content, &response); err != nil {
				log.Printf("Failed to decode CE-134 response from peer %v: %v", g.ValidatorIndex, err)
				return
			}

			log.Printf("Received work-report hash and signature from peer %v:\n- Hash: %x\n- Signature: %x",
				g.ValidatorIndex, response.WorkReportHash, response.Signature)
		}(g)
	}

	// start local refinement in parallel
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, err := ProduceWorkReport(ctx, h.refine, h.serviceState, authOutput, coreIndex, bundle, buildSegmentRootLookup(segments))
		if err != nil {
			log.Printf("local refinement failed: %v", err)
		}
	}()

	// TODO compare work results

	wg.Wait()

	return nil
}

// TODO: Build segment-root mappings based on historical data
func (h *WorkPackageSharer) buildSegmentRootMapping(pkg work.PackageBundle) []SegmentRootMapping {
	return []SegmentRootMapping{}
}

// SendWorkPackage transmits the work-package bundle to a specific guarantor.
func (h *WorkPackageSharer) sendWorkPackage(
	ctx context.Context,
	stream quic.Stream,
	coreIndex uint16,
	imported []SegmentRootMapping,
	bundle work.PackageBundle,
) error {
	msg1, err := jam.Marshal(struct {
		CoreIndex          uint16
		SegmentRootMapping []SegmentRootMapping
	}{
		CoreIndex:          coreIndex,
		SegmentRootMapping: imported,
	})
	if err != nil {
		return fmt.Errorf("failed to marshal first message: %w", err)
	}

	// 1st: “CoreIndex ++ Segments-Root Mappings”
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

	return nil
}
