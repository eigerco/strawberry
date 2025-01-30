package results

import (
	"fmt"
	"math"

	"github.com/eigerco/strawberry/internal/block"
	"github.com/eigerco/strawberry/internal/common"
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/erasurecoding"
	"github.com/eigerco/strawberry/internal/merkle/binary_tree"
	"github.com/eigerco/strawberry/internal/work"
	"github.com/eigerco/strawberry/pkg/serialization/codec/jam"
)

type AuthPVMInvoker interface {
	InvokePVM(workPackage work.Package, coreIndex uint16) ([]byte, error)
}

type RefinePVMInvoker interface {
	InvokePVM(
		serviceCodePredictionHash crypto.Hash,
		gas uint64,
		serviceIndex block.ServiceId,
		workPackageHash crypto.Hash,
		workPayload []byte,
		refinementContext block.RefinementContext,
		authorizerHash crypto.Hash,
		authorizerHashOutput []byte,
		importedSegments []work.Segment,
		extrinsicData [][]byte,
		exportOffset uint64,
	) ([]byte, []work.Segment, error)
}

type Computation struct {
	Auth               AuthPVMInvoker
	Refine             RefinePVMInvoker
	SegmentRoots       map[crypto.Hash]crypto.Hash // H⊞ -> H (14.12)
	SegmentData        map[crypto.Hash][]byte      // H -> []byte
	ExtrinsicPreimages map[crypto.Hash][]byte      // extrinsic hash -> payload
}

// NewComputation constructs a struct with injected data sources (maps for now)
func NewComputation(
	auth AuthPVMInvoker,
	refine RefinePVMInvoker,
	segmentRoots map[crypto.Hash]crypto.Hash,
	segmentData map[crypto.Hash][]byte,
	extrinsicPreimages map[crypto.Hash][]byte,
) *Computation {
	return &Computation{
		Auth:               auth,
		Refine:             refine,
		SegmentRoots:       segmentRoots,
		SegmentData:        segmentData,
		ExtrinsicPreimages: extrinsicPreimages,
	}
}

// L(r ∈ H ∪ H⊞) ≡ r if r ∈ H; l[h] if r = h⊞ (14.12 v0.5.4)
func (c *Computation) lookup(hash crypto.Hash) crypto.Hash {
	if root, exists := c.SegmentRoots[hash]; exists {
		return root
	}
	return hash
}

// ensures (h → e) (14.13 v0.5.4)
func (c *Computation) validateSegmentRootLookup() error {
	// (h → e)
	for h, e := range c.SegmentRoots {
		if _, exists := c.SegmentData[e]; !exists {
			return fmt.Errorf("invalid segment root mapping: work-package hash %x maps to unknown segment %x", h, e)
		}
	}
	// TODO: requires historical lookups to fully validate (14.13 v0.5.4)
	return nil
}

// X(w) = [d | (H(d), |d|) ∈ w.x] (14.14 v0.5.4)
func (c *Computation) buildExtrinsicData(item work.Item) ([][]byte, error) {
	var xW [][]byte
	for _, extr := range item.Extrinsics {
		preimage, exists := c.ExtrinsicPreimages[extr.Hash]
		if !exists {
			return nil, fmt.Errorf("missing extrinsic data for hash %x", extr.Hash)
		}
		if len(preimage) != int(extr.Length) {
			return nil, fmt.Errorf("extrinsic length mismatch for hash %x", extr.Hash)
		}

		xW = append(xW, preimage)
	}
	return xW, nil
}

// S(w) = [s[n] | M(s) = L(r), (r, n) ∈ w.i] (14.14 v0.5.4)
func (c *Computation) buildImportedSegments(item work.Item) ([]work.Segment, crypto.Hash, error) {
	var segments []work.Segment

	for _, imp := range item.ImportedSegments {
		root := c.lookup(imp.Hash)

		data, exists := c.SegmentData[root]
		if !exists {
			return nil, crypto.Hash{}, fmt.Errorf("missing segment data for root %x", root)
		}

		var seg work.Segment
		copy(seg[:], data)
		segments = append(segments, seg)
	}

	if len(segments) == 0 {
		return segments, crypto.Hash{}, nil
	}
	segBlobs := segmentsToByteSlices(segments)
	sRoot := binary_tree.ComputeConstantDepthRoot(segBlobs, crypto.HashData)
	return segments, sRoot, nil
}

// J(w) = [↕J₀(s, n) | M(s) = L(r), (r, n) ∈ w.i] (14.14 v0.5.4)
func (c *Computation) buildJustificationData(item work.Item) ([][]byte, crypto.Hash, error) {
	var jData [][]byte
	var importedSegments []work.Segment

	for _, imp := range item.ImportedSegments {
		root := c.lookup(imp.Hash)
		data, exists := c.SegmentData[root]
		if !exists {
			return nil, crypto.Hash{}, fmt.Errorf("missing data for root %x", root)
		}

		var seg work.Segment
		copy(seg[:], data)
		importedSegments = append(importedSegments, seg)
	}

	if len(importedSegments) == 0 {
		return nil, crypto.Hash{}, nil
	}
	segBlobs := segmentsToByteSlices(importedSegments)

	for _, imp := range item.ImportedSegments {
		pageProof := binary_tree.GeneratePageProof(
			segBlobs,       // s
			int(imp.Index), // n
			0,
			crypto.HashData,
		)

		// Convert proof to byte format
		proofBytes := flattenPageProof(pageProof)
		jData = append(jData, proofBytes)
	}

	if len(jData) == 0 {
		return jData, crypto.Hash{}, nil
	}
	jRoot := binary_tree.ComputeConstantDepthRoot(jData, crypto.HashData)
	return jData, jRoot, nil
}

// b = p || X(w) || S(w) || J(w) (14.14 v0.5.4)
func (c *Computation) buildAuditableWorkPackage(pkg work.Package) ([]byte, error) {
	wpBytes, err := jam.Marshal(pkg)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal package: %w", err)
	}
	auditable := make([]byte, 0, len(wpBytes))
	auditable = append(auditable, wpBytes...)

	for _, item := range pkg.WorkItems {
		xW, err := c.buildExtrinsicData(item)
		if err != nil {
			return nil, err
		}
		auditable = append(auditable, flattenBlobs(xW)...)

		sSegments, sRoot, err := c.buildImportedSegments(item)
		if err != nil {
			return nil, err
		}
		auditable = append(auditable, flattenBlobs(segmentsToByteSlices(sSegments))...)
		auditable = append(auditable, sRoot[:]...)

		jBlobs, jRoot, err := c.buildJustificationData(item)
		if err != nil {
			return nil, err
		}
		auditable = append(auditable, flattenBlobs(jBlobs)...)
		auditable = append(auditable, jRoot[:]...)
	}

	return auditable, nil
}

// A(h,b,s) (14.16 v0.5.4)
func (c *Computation) computeAvailabilitySpecifier(
	packageHash crypto.Hash,
	auditableBlob []byte,
	exportedSegments []work.Segment,
) (block.WorkPackageSpecification, error) {
	l := len(auditableBlob)
	if l > math.MaxUint32 {
		return block.WorkPackageSpecification{}, fmt.Errorf("auditable blob too large")
	}
	auditLen := uint32(l)

	segBlobs := segmentsToByteSlices(exportedSegments)
	e := binary_tree.ComputeConstantDepthRoot(segBlobs, crypto.HashData)

	n := uint16(len(exportedSegments))

	// H#(C⌈|b|/WE⌉(PWE(b)))
	padded := work.ZeroPadding(auditableBlob, common.ErasureCodingChunkSize)
	shards, err := erasurecoding.Encode(padded)
	if err != nil {
		return block.WorkPackageSpecification{}, err
	}
	if len(shards) == 0 {
		return block.WorkPackageSpecification{}, nil
	}
	bClubs := binary_tree.ComputeWellBalancedRoot(shards, crypto.HashData)

	// M#_B(T C#_6 (s ⌢ P(s)))
	pagedProofs, err := ComputePagedProofs(exportedSegments)
	if err != nil {
		return block.WorkPackageSpecification{}, fmt.Errorf("failed to compute paged proofs: %w", err)
	}

	combinedSegments := append(segmentsToByteSlices(exportedSegments), segmentsToByteSlices(pagedProofs)...)
	combined := flattenBlobs(combinedSegments)

	shards, err = erasurecoding.Encode(combined)
	if err != nil {
		return block.WorkPackageSpecification{}, err
	}
	if len(shards) == 0 {
		return block.WorkPackageSpecification{}, nil
	}
	sClubs := binary_tree.ComputeWellBalancedRoot(shards, crypto.HashData)

	blobs := [][]byte{bClubs[:], sClubs[:]}
	u := binary_tree.ComputeWellBalancedRoot(blobs, crypto.HashData)

	spec := block.WorkPackageSpecification{
		WorkPackageHash:           packageHash,
		AuditableWorkBundleLength: auditLen,
		ErasureRoot:               u,
		SegmentRoot:               e,
		SegmentCount:              n,
	}
	return spec, nil
}

// EvaluateWorkPackage Ξ : (P, N_C) → W (14.11 v0.5.4)
func (c *Computation) EvaluateWorkPackage(
	wp work.Package,
	coreIndex uint16,
) (*block.WorkReport, error) {
	if err := wp.ValidateNumberOfEntries(); err != nil {
		return nil, err
	}
	if err := wp.ValidateSize(); err != nil {
		return nil, err
	}
	if err := wp.ValidateGas(); err != nil {
		return nil, err
	}
	if err := c.validateSegmentRootLookup(); err != nil {
		return nil, err
	}

	audBlob, err := c.buildAuditableWorkPackage(wp)
	if err != nil {
		return nil, fmt.Errorf("failed to build auditable work-package: %w", err)
	}

	// ΨI (p, c)
	authOutput, err := c.Auth.InvokePVM(wp, coreIndex)
	if err != nil {
		return nil, fmt.Errorf("authorization: %w", err)
	}

	var allWorkResults []block.WorkResult
	var allExportedSegments []work.Segment
	exportOffset := uint64(0)

	for _, item := range wp.WorkItems {
		importedSegs, _, err := c.buildImportedSegments(item)
		if err != nil {
			return nil, fmt.Errorf("importedSegments: %w", err)
		}

		extrinsicData, err := c.buildExtrinsicData(item)
		if err != nil {
			return nil, fmt.Errorf("extrinsicData: %w", err)
		}

		// ΨR(wc, wg, ws, h, wy, px, pa, o, S(w,l), X(w), l) (14.11 v0.5.4)
		refineOut, exported, refineErr := c.Refine.InvokePVM(
			item.CodeHash,
			item.GasLimitRefine,
			block.ServiceId(item.ServiceId),
			crypto.HashData(wp.Parameterization),
			item.Payload,
			wp.Context,
			wp.AuthCodeHash,
			authOutput,
			importedSegs,
			extrinsicData,
			exportOffset,
		)

		var out block.WorkResultOutputOrError
		var finalExported []work.Segment

		// I(p, j)
		if refineErr != nil {
			out = block.WorkResultOutputOrError{Inner: block.UnexpectedTermination}
			finalExported = make([]work.Segment, item.ExportedSegments)
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

		wr := item.ToWorkResult(out)
		allWorkResults = append(allWorkResults, wr)
		allExportedSegments = append(allExportedSegments, finalExported...)
		exportOffset += uint64(item.ExportedSegments)
	}

	wpBytes, err := jam.Marshal(wp)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize work-package: %w", err)
	}

	availSpec, err := c.computeAvailabilitySpecifier(
		crypto.HashData(wpBytes),
		audBlob,
		allExportedSegments,
	)
	if err != nil {
		return nil, fmt.Errorf("failed computing availability spec: %w", err)
	}

	// (s, x : px, c, a : pa, o, l, r)
	return &block.WorkReport{
		WorkPackageSpecification: availSpec,
		RefinementContext:        wp.Context,
		CoreIndex:                coreIndex,
		AuthorizerHash:           crypto.HashData(authOutput),
		Output:                   authOutput,
		WorkResults:              allWorkResults,
		SegmentRootLookup:        c.SegmentRoots,
	}, nil
}

// ComputePagedProofs P(s) → [E(J₆(s,i), L₆(s,i))₍l₎ | i ∈ ℕ₍⌈|s|/64⌉₎] (14.10 v0.5.4)
func ComputePagedProofs(segments []work.Segment) ([]work.Segment, error) {
	if len(segments) == 0 {
		return nil, fmt.Errorf("no segments provided")
	}
	blobs := make([][]byte, len(segments))
	for i, seg := range segments {
		blobs[i] = seg[:]
	}
	numPages := (len(segments) + work.SegmentsPerPage - 1) / work.SegmentsPerPage
	pagedProofs := make([]work.Segment, numPages)
	for pageIndex := 0; pageIndex < numPages; pageIndex++ {
		// Get leaf hashes and proof for page
		leafHashes := binary_tree.GetLeafPage(blobs, pageIndex, common.NumberOfErasureCodecPiecesInSegment, crypto.HashData)
		proof := binary_tree.GeneratePageProof(blobs, pageIndex, common.NumberOfErasureCodecPiecesInSegment, crypto.HashData)

		// Encode leaves and proof
		marshalledLeaves, err := jam.Marshal(leafHashes)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal leaf hashes: %w", err)
		}
		marshalledProof, err := jam.Marshal(proof)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal proof: %w", err)
		}
		combined := append(marshalledLeaves, marshalledProof...)
		padded := work.ZeroPadding(combined, common.SizeOfSegment)
		copy(pagedProofs[pageIndex][:], padded)
	}
	return pagedProofs, nil
}

func flattenBlobs(blobs [][]byte) []byte {
	size := 0
	for _, b := range blobs {
		size += len(b)
	}
	out := make([]byte, 0, size)
	for _, b := range blobs {
		out = append(out, b...)
	}
	return out
}

func segmentsToByteSlices(segs []work.Segment) [][]byte {
	out := make([][]byte, len(segs))
	for i := range segs {
		out[i] = segs[i][:]
	}
	return out
}

func flattenPageProof(proof []crypto.Hash) []byte {
	var out []byte
	for _, h := range proof {
		out = append(out, h[:]...)
	}
	return out
}
