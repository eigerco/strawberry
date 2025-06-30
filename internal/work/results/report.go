package results

import (
	"fmt"

	"github.com/eigerco/strawberry/internal/block"
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/merkle/binary_tree"
	"github.com/eigerco/strawberry/internal/refine"
	"github.com/eigerco/strawberry/internal/service"
	"github.com/eigerco/strawberry/internal/work"
	"github.com/eigerco/strawberry/pkg/serialization/codec/jam"
)

// ProduceWorkReport runs the refine invocation and returns the work report
func ProduceWorkReport(
	refine refine.RefinePVMInvoker,
	serviceState service.ServiceState,
	authOutput []byte,
	coreIndex uint16,
	bundle *work.PackageBundle,
	segmentRootLookup work.SegmentRootLookup,
) (*Shards, block.WorkReport, error) {
	var allWorkResults []block.WorkResult
	var allExportedSegments []work.Segment
	var reportSegmentRootLookup = make(map[crypto.Hash]crypto.Hash)
	exportOffset := uint64(0)

	for index, item := range bundle.Package().WorkItems {
		segments, err := bundle.ItemImportedSegments(index)
		if err != nil {
			return nil, block.WorkReport{}, err
		}
		refineOut, exported, gasUsed, refineErr := refine.InvokePVM(
			uint32(index),
			bundle.Package(),
			authOutput,
			segments,
			exportOffset,
		)

		var out block.WorkResultOutputOrError
		var finalExported []work.Segment

		if refineErr != nil {
			out = block.WorkResultOutputOrError{Inner: block.UnexpectedTermination}
		} else {
			out = block.WorkResultOutputOrError{Inner: refineOut}
			actual, expected := len(exported), int(item.ExportedSegments)
			switch {
			case actual < expected:
				diff := expected - actual
				zeros := make([]work.Segment, diff)
				finalExported = append(exported, zeros...)
			case actual > expected:
				finalExported = exported[:expected]
			default:
				finalExported = exported
			}
		}

		wr := item.ToWorkResult(out, gasUsed)
		allWorkResults = append(allWorkResults, wr)
		allExportedSegments = append(allExportedSegments, finalExported...)
		exportOffset += uint64(item.ExportedSegments)
		for _, seg := range item.ImportedSegments {
			// K(l) ≡ {h | w ∈ p.w, (h⊞, n) ∈ w.i}
			// if we find an entry with work-package hash this means it's not a segment-root and so
			// it must be added to the segment root lookup dictionary for the final report
			segmentRoot, exists := segmentRootLookup[seg.Hash]
			if exists {
				reportSegmentRootLookup[seg.Hash] = segmentRoot
			}
		}
	}
	// |l| ≤ 8 (eq. 14.11) check that there are no more than 8 segment lookups
	if len(reportSegmentRootLookup) > 8 {
		return nil, block.WorkReport{}, fmt.Errorf("too many segment root lookups in the work package, no more than 8 lookups allowed")
	}

	pkg := bundle.Package()

	auditableBlob, err := jam.Marshal(bundle)
	if err != nil {
		return nil, block.WorkReport{}, fmt.Errorf("failed to encode auditable backage: %w", err)
	}

	// Compute shards to construct the availability specifier and return them to be stored later
	shardData, err := ShardBundleAndSegments(auditableBlob, allExportedSegments)
	if err != nil {
		return nil, block.WorkReport{}, fmt.Errorf("failed to shard data: %w", err)
	}

	// Compute the auth hash
	_, authHash, err := pkg.ComputeAuthorizerHashes(serviceState)
	if err != nil {
		return nil, block.WorkReport{}, fmt.Errorf("failed to compute authorizer hash: %w", err)
	}

	pkgBytes, err := bundle.EncodedPackage()
	if err != nil {
		return nil, block.WorkReport{}, fmt.Errorf("failed to encode work package: %w", err)
	}

	// (s, x : px, c, a : pa, o, l, r)
	return shardData, block.WorkReport{
		WorkPackageSpecification: block.WorkPackageSpecification{ // eq. 14.16
			WorkPackageHash:           crypto.HashData(pkgBytes),
			AuditableWorkBundleLength: uint32(len(auditableBlob)),
			ErasureRoot:               binary_tree.ComputeWellBalancedRoot(shardData.BundleHashAndSegmentsRoot, crypto.HashData),
			SegmentRoot:               binary_tree.ComputeConstantDepthRoot(segmentsToByteSlices(allExportedSegments), crypto.HashData),
			SegmentCount:              uint16(len(allExportedSegments)),
		},
		RefinementContext: bundle.Package().Context,
		CoreIndex:         coreIndex,
		Trace:             authOutput,
		AuthorizerHash:    authHash,
		SegmentRootLookup: reportSegmentRootLookup,
		WorkResults:       allWorkResults,
	}, nil
}
