package work

import (
	"maps"
	"math/rand/v2"
	"slices"
	"testing"

	"github.com/eigerco/strawberry/internal/block"
	"github.com/eigerco/strawberry/internal/constants"
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/merkle/binary_tree"
	"github.com/eigerco/strawberry/internal/testutils"
	"github.com/eigerco/strawberry/pkg/serialization/codec/jam"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPackageBundleBuildingAndCodec(t *testing.T) {
	gen := newBundleGenerator(t)
	generatedBundle := gen.random(t)
	encodedPackage, err := jam.Marshal(generatedBundle.Package())
	require.NoError(t, err)

	// should use jam.Marshal for encoding
	generatedBundlePackage, err := generatedBundle.EncodedPackage()
	require.NoError(t, err)
	assert.Equal(t, encodedPackage, generatedBundlePackage)

	encodedBundle, err := jam.Marshal(generatedBundle)
	require.NoError(t, err)

	// after we used jam.Marshal should get from cache
	generatedBundlePackage, err = generatedBundle.EncodedPackage()
	require.NoError(t, err)
	assert.Equal(t, encodedPackage, generatedBundlePackage)

	decodedBundle := &PackageBundle{}
	err = jam.Unmarshal(encodedBundle, decodedBundle)
	require.NoError(t, err)

	assert.Equal(t, generatedBundle.pkg, decodedBundle.Package())
	assert.Equal(t, generatedBundle.extrinsics, decodedBundle.extrinsics)
	assert.Equal(t, generatedBundle.justifications, decodedBundle.justifications)

	// should use the original cache and not encode again
	decodedBundlePackage, err := decodedBundle.EncodedPackage()
	require.NoError(t, err)
	assert.Equal(t, encodedPackage, decodedBundlePackage)

	decodedBundleEncoded, err := jam.Marshal(decodedBundle)
	require.NoError(t, err)

	assert.Equal(t, encodedBundle, decodedBundleEncoded)

	pkg := generatedBundle.Package()
	for i := range pkg.WorkItems {
		pkg.WorkItems[i].ImportedSegments = append(pkg.WorkItems[i].ImportedSegments, ImportedSegment{
			Hash:  testutils.RandomHash(t), // invalid reference
			Index: 10010,
		})
	}
	builder, err := NewPackageBundleBuilder(pkg, gen.segmentLookup, gen.segmentsPool, slices.Concat(gen.extrinsics...))
	require.NoError(t, err)
	_, err = builder.Build()
	assert.ErrorContains(t, err, "missing segment data for root")

	pkg = generatedBundle.Package()
	for i := range pkg.WorkItems {
		pkg.WorkItems[i].Extrinsics = append(pkg.WorkItems[i].Extrinsics, Extrinsic{
			Hash:   testutils.RandomHash(t), // invalid reference
			Length: 100,
		})
	}
	_, err = NewPackageBundleBuilder(pkg, gen.segmentLookup, gen.segmentsPool, slices.Concat(gen.extrinsics...))
	assert.ErrorContains(t, err, "invalid extrinsic reference")
}

type bundleGenerator struct {
	segmentsPool  map[crypto.Hash][]Segment
	segmentLookup map[crypto.Hash]crypto.Hash
	extrinsics    [][]byte
}

func newBundleGenerator(t *testing.T) *bundleGenerator {
	t.Helper()

	sp := &bundleGenerator{
		segmentsPool:  make(map[crypto.Hash][]Segment),
		segmentLookup: make(map[crypto.Hash]crypto.Hash),
	}
	for range rand.Uint32N(10) + 1 {
		nrOfSegments := rand.Uint32N(10) + 1
		segments := make([]Segment, nrOfSegments)
		for i := range nrOfSegments {
			segments[i] = Segment(testutils.RandomBytes(t, constants.SizeOfSegment))
		}
		segmentRoot := binary_tree.ComputeConstantDepthRoot(segmentsToByteSlices(segments), crypto.HashData)
		sp.segmentsPool[segmentRoot] = segments
	}
	for segmentRoot := range sp.segmentsPool {
		sp.segmentLookup[testutils.RandomHash(t)] = segmentRoot
	}
	return sp
}

func (s *bundleGenerator) random(t *testing.T) *PackageBundle {
	t.Helper()

	pkg := Package{
		AuthorizationToken: testutils.RandomBytes(t, rand.Uint32N(100)),
		AuthorizerService:  testutils.RandomUint32(),
		AuthCodeHash:       testutils.RandomHash(t),
		Parameterization:   testutils.RandomBytes(t, rand.Uint32N(100)),
		Context: block.RefinementContext{
			Anchor: block.RefinementContextAnchor{
				HeaderHash:         testutils.RandomHash(t),
				PosteriorStateRoot: testutils.RandomHash(t),
				PosteriorBeefyRoot: testutils.RandomHash(t),
			},
			LookupAnchor: block.RefinementContextLookupAnchor{
				HeaderHash: testutils.RandomHash(t),
				Timeslot:   testutils.RandomTimeslot(),
			},
			PrerequisiteWorkPackage: slices.Collect(testutils.RandomSlice(t, 1, 10, testutils.RandomHash)),
		},
		WorkItems: slices.Collect(testutils.RandomSlice(t, 1, 10, s.randomWorkItem)),
	}
	builder, err := NewPackageBundleBuilder(pkg, s.segmentLookup, s.segmentsPool, slices.Concat(s.extrinsics...))
	require.NoError(t, err)

	bundle, err := builder.Build()
	require.NoError(t, err)

	return bundle
}

func (s *bundleGenerator) assignSegmentsToItem(item *Item, nrOfSegments int) {
	segmentsRoots := slices.Collect(maps.Keys(s.segmentsPool))

	for range nrOfSegments {
		segmentsRoot := segmentsRoots[rand.IntN(len(segmentsRoots))]
		item.ImportedSegments = append(item.ImportedSegments, ImportedSegment{
			Hash:  segmentsRoot,
			Index: uint16(rand.IntN(len(s.segmentsPool[segmentsRoot]))),
		})
	}
}

func (s *bundleGenerator) assignSegmentsToItemWPHash(item *Item, nrOfSegments int) {
	wpHashes := slices.Collect(maps.Keys(s.segmentLookup))

	for range nrOfSegments {
		wpHash := wpHashes[rand.IntN(len(wpHashes))]
		segmentsRoot := s.segmentLookup[wpHash]
		item.ImportedSegments = append(item.ImportedSegments, ImportedSegment{
			Hash:  wpHash,
			Index: uint16(rand.IntN(len(s.segmentsPool[segmentsRoot]))),
		})
	}
}

func (s *bundleGenerator) randomWorkItem(t *testing.T) Item {
	item := Item{
		ServiceId:          block.ServiceId(testutils.RandomUint32()),
		CodeHash:           testutils.RandomHash(t),
		Payload:            testutils.RandomBytes(t, rand.Uint32N(100)),
		GasLimitRefine:     testutils.RandomUint64(),
		GasLimitAccumulate: testutils.RandomUint64(),
		ExportedSegments:   uint16(testutils.RandomUint32()),
	}

	s.assignSegmentsToItem(&item, rand.IntN(5))
	s.assignSegmentsToItemWPHash(&item, rand.IntN(5))
	for range rand.IntN(5) {
		extrinsic := testutils.RandomBytes(t, rand.Uint32N(100))
		item.Extrinsics = append(item.Extrinsics, Extrinsic{
			Hash:   crypto.HashData(extrinsic),
			Length: uint32(len(extrinsic)),
		})
		s.extrinsics = append(s.extrinsics, extrinsic)
	}
	return item
}
