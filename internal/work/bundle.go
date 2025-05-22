package work

import (
	"fmt"
	"io"
	"slices"

	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/merkle/binary_tree"
	"github.com/eigerco/strawberry/pkg/serialization/codec/jam"
)

// PackageBundle represents the auditable bundle
type PackageBundle struct {
	pkg Package

	// The results of X(w), S(w), J(w) by work item index from eq. 14.14
	extrinsics       [][][]byte
	importedSegments [][]Segment
	justifications   [][][]crypto.Hash

	// cash the encoded bundle so we don't unnecessarily marsha/unmarshal it
	bytes []byte
	// keep the offset so we can only get the encoded package when needed
	bytesPkgOffset int
}

func (b *PackageBundle) Package() Package {
	return b.pkg
}

// ItemImportedSegments holds the actual segments for a work-item or the result of S(w ∈ I)
func (b *PackageBundle) ItemImportedSegments(itemIndex int) ([]Segment, error) {
	if itemIndex >= len(b.importedSegments) {
		return nil, fmt.Errorf("requested item with index %d from a total of %d work-items", itemIndex, len(b.importedSegments))
	}
	return b.importedSegments[itemIndex], nil
}

// EncodedPackage returns the encoded package from cache if present, if not marshals it
func (b *PackageBundle) EncodedPackage() ([]byte, error) {
	if b.bytes != nil && len(b.bytes) >= b.bytesPkgOffset {
		return b.bytes[:b.bytesPkgOffset], nil
	}
	bb, err := jam.Marshal(b.pkg)
	if err != nil {
		return nil, err
	}
	return bb, nil
}

// MarshalJAM returns the encoded bundle from cache if present and if not marshals the entire bundle and keeps it cached
func (b *PackageBundle) MarshalJAM() ([]byte, error) {
	if b.bytes != nil {
		return b.bytes, nil
	}

	bb, err := jam.Marshal(b.pkg)
	if err != nil {
		return nil, err
	}
	b.bytes = append(b.bytes, bb...)
	b.bytesPkgOffset = len(bb)

	// encode without length discriminator which is equivalent with just flattening the bytes
	// this is ok because the work items contain the extrinsics lengths so there won't be a problem decoding it
	b.bytes = append(b.bytes, slices.Concat(slices.Concat(b.extrinsics...)...)...)

	for _, s := range slices.Concat(b.importedSegments...) {
		bb, err = jam.Marshal(s)
		if err != nil {
			return nil, err
		}
		b.bytes = append(b.bytes, bb...)
	}
	for _, j := range slices.Concat(b.justifications...) {
		bb, err = jam.Marshal(j)
		if err != nil {
			return nil, err
		}
		b.bytes = append(b.bytes, bb...)
	}
	return b.bytes, nil
}

func (b *PackageBundle) UnmarshalJAM(reader io.Reader) error {
	cReader := &cacheReader{reader: reader}
	dec := jam.NewDecoder(cReader)
	if err := dec.Decode(&b.pkg); err != nil {
		return fmt.Errorf("error decoding package: %w", err)
	}

	b.bytesPkgOffset = len(cReader.cache)
	b.extrinsics = make([][][]byte, len(b.pkg.WorkItems))
	b.importedSegments = make([][]Segment, len(b.pkg.WorkItems))
	b.justifications = make([][][]crypto.Hash, len(b.pkg.WorkItems))
	for i, item := range b.pkg.WorkItems {
		for _, x := range item.Extrinsics {
			extrinsicData := make([]byte, x.Length)
			if err := dec.DecodeFixedLength(&extrinsicData, uint(x.Length)); err != nil {
				return fmt.Errorf("error decoding extrinsic data: %w", err)
			}
			b.extrinsics[i] = append(b.extrinsics[i], extrinsicData)
		}
	}
	for i, item := range b.pkg.WorkItems {
		for range item.ImportedSegments {
			segmentData := Segment{}
			if err := dec.Decode(&segmentData); err != nil {
				return fmt.Errorf("error decoding import segment data: %w", err)
			}
			b.importedSegments[i] = append(b.importedSegments[i], segmentData)
		}
	}
	for i, item := range b.pkg.WorkItems {
		for range item.ImportedSegments {
			justificationData := []crypto.Hash{}
			if err := dec.Decode(&justificationData); err != nil {
				return fmt.Errorf("error decoding import segment data: %w", err)
			}
			b.justifications[i] = append(b.justifications[i], justificationData)
		}
	}
	b.bytes = cReader.cache
	return nil
}

// implements io.Reader and intercepts the red bytes so we can cache it
type cacheReader struct {
	cache  []byte
	reader io.Reader
}

func (c *cacheReader) Read(p []byte) (n int, err error) {
	n, err = c.reader.Read(p)
	if err != nil {
		return n, err
	}
	c.cache = append(c.cache, p[:n]...)
	return n, err
}

func NewPackageBundleBuilder(pkg Package, segmentRootLookup map[crypto.Hash]crypto.Hash, importedSegments map[crypto.Hash][]Segment, extrinsics []byte) (*PackageBundleBuilder, error) {
	extrinsicsMap := map[crypto.Hash][]byte{}
	offset := uint32(0)
	for itemIndex, item := range pkg.WorkItems {
		for extrIndex, extr := range item.Extrinsics {
			if int(offset+extr.Length) > len(extrinsics) {
				return nil, fmt.Errorf("extrinsic data provided too small, expected length %d for item %d extrinsic %d", extr.Length, itemIndex, extrIndex)
			}
			extrinsicData := extrinsics[offset : offset+extr.Length]
			extrHash := crypto.HashData(extrinsicData)
			if extr.Hash != extrHash {
				return nil, fmt.Errorf("extrinsic hash provided in the work-package does not match the one from provided extrinsic")
			}
			extrinsicsMap[extrHash] = extrinsicData
			offset += extr.Length
		}
	}

	return &PackageBundleBuilder{
		pkg:               pkg,
		segmentRootLookup: segmentRootLookup,
		importedSegments:  importedSegments,
		extrinsics:        extrinsicsMap,
	}, nil
}

type SegmentRootLookup map[crypto.Hash]crypto.Hash

// Lookup L(r ∈ H ∪ H⊞) ≡ r if r ∈ H; l[h] if r = h⊞ (14.12)
func (l SegmentRootLookup) Lookup(hash crypto.Hash) crypto.Hash {
	if root, exists := l[hash]; exists {
		return root
	}
	return hash
}

type PackageBundleBuilder struct {
	pkg Package

	// The mapping of work package hash to the import segments' merkle root (H⊞ -> H)
	segmentRootLookup SegmentRootLookup
	// The mapping of import segments' merkle root to the import segments in question (M(b) -> [G])
	importedSegments map[crypto.Hash][]Segment
	// External data or preimage (H -> Y)
	extrinsics map[crypto.Hash][]byte
}

func (b *PackageBundleBuilder) Build() (bundle *PackageBundle, err error) {
	bundle = &PackageBundle{
		pkg:              b.pkg,
		extrinsics:       make([][][]byte, len(b.pkg.WorkItems)),
		importedSegments: make([][]Segment, len(b.pkg.WorkItems)),
		justifications:   make([][][]crypto.Hash, len(b.pkg.WorkItems)),
	}
	for i, item := range b.pkg.WorkItems {
		bundle.extrinsics[i], err = b.buildExtrinsicData(item)
		if err != nil {
			return nil, err
		}
		bundle.importedSegments[i], err = b.buildImportedSegments(item)
		if err != nil {
			return nil, err
		}
		bundle.justifications[i], err = b.buildJustificationData(item)
		if err != nil {
			return nil, err
		}
	}
	return bundle, nil
}

// X(w) = [d | (H(d), |d|) ∈ w.x] (14.14 v0.5.4)
func (b *PackageBundleBuilder) buildExtrinsicData(item Item) ([][]byte, error) {
	var xW [][]byte
	for _, extr := range item.Extrinsics {
		preimage, exists := b.extrinsics[extr.Hash]
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
func (b *PackageBundleBuilder) buildImportedSegments(item Item) ([]Segment, error) {
	segments := make([]Segment, len(item.ImportedSegments))
	for i, imp := range item.ImportedSegments {
		root := b.segmentRootLookup.Lookup(imp.Hash)

		data, exists := b.importedSegments[root]
		if !exists {
			return nil, fmt.Errorf("missing segment data for root %x", root)
		}
		if int(imp.Index) > len(data) {
			return nil, fmt.Errorf("invalid segment index for root %d", imp.Index)
		}
		segments[i] = data[imp.Index]
	}
	return segments, nil
}

// J(w) = [↕J₀(s, n) | M(s) = L(r), (r, n) ∈ w.i] (14.14 v0.5.4)
func (b *PackageBundleBuilder) buildJustificationData(item Item) ([][]crypto.Hash, error) {
	justifications := make([][]crypto.Hash, len(item.ImportedSegments))
	for i, imp := range item.ImportedSegments {
		root := b.segmentRootLookup.Lookup(imp.Hash)
		data, exists := b.importedSegments[root]
		if !exists {
			return nil, fmt.Errorf("missing data for root %x", root)
		}

		pageProof := binary_tree.GeneratePageProof(segmentsToByteSlices(data), int(imp.Index), 0, crypto.HashData)
		if len(pageProof) == 0 {
			continue
		}
		justifications[i] = pageProof
	}

	if len(justifications) == 0 {
		return nil, nil
	}
	return justifications, nil
}

func segmentsToByteSlices(segs []Segment) [][]byte {
	out := make([][]byte, len(segs))
	for i := range segs {
		out[i] = segs[i][:]
	}
	return out
}
