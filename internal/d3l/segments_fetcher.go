package d3l

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"log"

	"github.com/eigerco/strawberry/internal/common"
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/erasurecoding"
	"github.com/eigerco/strawberry/internal/work"
	"github.com/eigerco/strawberry/pkg/network/peer"
)

// SegmentsFetcher defines an interface for fetching imported segments from the availability system
type SegmentsFetcher interface {

	// Fetch fetches enough segment shards from the availability system to reconstructs the requested segments
	// the availability system expects to request the shards by the erasure-root
	// however we request the segments by segment-root,
	// to tackle this problem the SegmentsFetcher keeps internally a dictionary of segment-root to erasure-root mappings
	Fetch(ctx context.Context, segmentRoot crypto.Hash, segmentIndexes ...uint16) ([]work.Segment, error)
}

// AssurerClient
type AssurerClient interface {
	SegmentShardRequestSend(ctx context.Context, peerKey ed25519.PublicKey, erasureRoot crypto.Hash, shardIndex uint16, segmentIndexes []uint16) (segmentShards [][]byte, err error)
	GetAllPeers() []*peer.Peer
}

// NewSegmentsFetcher creates a basic segments fetcher
func NewSegmentsFetcher(assurerClient AssurerClient, segmentRootToErasureRoot map[crypto.Hash]crypto.Hash) SegmentsFetcher {
	return &segmentsFetcher{
		assurerClient:            assurerClient,
		segmentRootToErasureRoot: segmentRootToErasureRoot,
	}
}

// segmentsFetcher implements SegmentsFetcher
type segmentsFetcher struct {
	assurerClient AssurerClient

	segmentRootToErasureRoot map[crypto.Hash]crypto.Hash
}

// Fetch requests the shards from assurers, once it gathers 342 valid shards it will reconstruct the segments
func (m *segmentsFetcher) Fetch(ctx context.Context, segmentRoot crypto.Hash, segmentIndexes ...uint16) ([]work.Segment, error) {
	erasureRoot, ok := m.segmentRootToErasureRoot[segmentRoot]
	if !ok {
		return nil, fmt.Errorf("no erasure root for segment-root %v found", segmentRoot)
	}

	// Return early if no segments are present
	if len(segmentIndexes) == 0 {
		return nil, nil
	}

	shardsByIndex := map[uint16][][]byte{}
	nrOfShards := 0
	assurers := m.assurerClient.GetAllPeers()
	for _, assurer := range assurers {
		if assurer.ValidatorIndex == nil {
			log.Printf("no validator index found, skipping peer %x", assurer.Ed25519Key)
			continue
		}
		validatorIndex := *assurer.ValidatorIndex
		// TODO parallelize segment shards requests
		segmentShards, err := m.assurerClient.SegmentShardRequestSend(ctx, assurer.Ed25519Key, erasureRoot, validatorIndex, segmentIndexes)
		if err != nil {
			log.Printf("failed to fetch segment shard for hash %x indexes: %v err: %v", segmentRoot, segmentIndexes, err)
			continue
		}
		if len(segmentShards) != len(segmentIndexes) {
			log.Printf("failed to fetch segment shard for hash %x indexes: %v; got shards: %d", segmentRoot, segmentIndexes, len(segmentShards))
			continue
		}

		for i, segmentShard := range segmentShards {
			shardsByIndex[segmentIndexes[i]] = append(shardsByIndex[segmentIndexes[i]], segmentShard)
		}
		nrOfShards++

		// We have enough shards to reconstruct the segments no need to waste time querying all the other validators
		if nrOfShards >= common.ErasureCodingOriginalShards {
			break
		}
	}

	// Error if we didn't gather enough shards to reconstruct the segment
	if nrOfShards < common.ErasureCodingOriginalShards {
		return nil, fmt.Errorf("couldn't get enough shards for segment root=%x; got %d out of %d", segmentRoot, nrOfShards, common.ErasureCodingOriginalShards)
	}

	// Decode each segment for each index
	segments := make([]work.Segment, len(segmentIndexes))
	for i, segmentIndex := range segmentIndexes {
		segment, err := erasurecoding.Decode(shardsByIndex[segmentIndex], common.SizeOfSegment)
		if err != nil {
			return nil, fmt.Errorf("failed to decode segment with index %v: %w", segmentIndex, err)
		}
		segments[i] = work.Segment(segment)
	}

	return segments, nil
}
