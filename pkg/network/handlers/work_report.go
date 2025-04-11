package handlers

import (
	"context"
	"fmt"

	"github.com/eigerco/strawberry/internal/block"
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/refine"
	"github.com/eigerco/strawberry/internal/service"
	"github.com/eigerco/strawberry/internal/work"
)

// ProduceWorkReport runs the refine invocation and returns the work report
func ProduceWorkReport(
	ctx context.Context,
	refine refine.RefinePVMInvoker,
	serviceState service.ServiceState,
	authOutput []byte,
	coreIndex uint16,
	bundle work.PackageBundle,
	segmentRootLookup map[crypto.Hash]crypto.Hash,
) (*block.WorkReport, error) {
	var allWorkResults []block.WorkResult
	exportOffset := uint64(0)

	// TODO: pass the correct segment data (placeholder for now)
	var segments []work.Segment

	for index, item := range bundle.Package.WorkItems {
		refineOut, _, refineErr := refine.InvokePVM(
			uint32(index),
			bundle.Package,
			authOutput,
			segments,
			exportOffset,
		)

		var out block.WorkResultOutputOrError

		if refineErr != nil {
			out = block.WorkResultOutputOrError{Inner: block.UnexpectedTermination}
		} else {
			out = block.WorkResultOutputOrError{Inner: refineOut}
		}

		wr := item.ToWorkResult(out)
		allWorkResults = append(allWorkResults, wr)
		exportOffset += uint64(item.ExportedSegments)
	}

	_, authHash, err := bundle.Package.ComputeAuthorizerHashes(serviceState)
	if err != nil {
		return nil, fmt.Errorf("failed to compute authorizer hash: %w", err)
	}

	// (s, x : px, c, a : pa, o, l, r)
	workReport := &block.WorkReport{
		// TODO: WorkPackageSpecification (14.16) to be constructed as part of the availability logic
		RefinementContext: bundle.Package.Context,
		CoreIndex:         coreIndex,
		Output:            authOutput,
		AuthorizerHash:    authHash,
		SegmentRootLookup: segmentRootLookup,
		WorkResults:       allWorkResults,
	}

	return workReport, nil
}
