package validator

import (
	"context"
	"fmt"
	"github.com/eigerco/strawberry/internal/merkle/binary_tree"
	"github.com/eigerco/strawberry/internal/store"
	"slices"

	"github.com/eigerco/strawberry/internal/crypto"
)

// ValidatorService holds the logic for storing DA shards for availability purposes, and distributing the shards with
// justifications after the guarantors finished processing
type ValidatorService interface {
	ShardDistribution(ctx context.Context, erasureRoot crypto.Hash, shardIndex uint16) (bundleShard []byte, segmentShard [][]byte, justification [][]byte, err error)
	AuditShardRequest(ctx context.Context, erasureRoot crypto.Hash, shardIndex uint16) (bundleShard []byte, justification [][]byte, err error)
	SegmentShardRequest(ctx context.Context, erasureRoot crypto.Hash, shardIndex uint16, segmentIndexes []uint16) (segmentShards [][]byte, err error)
	SegmentShardRequestJustification(ctx context.Context, erasureRoot crypto.Hash, shardIndex uint16, segmentIndexes []uint16) (segmentShards [][]byte, justification [][][]byte, err error)
}

// NewService creates a new validator service that implements ValidatorService interface
func NewService(availabilityStore *store.Availability) ValidatorService {
	return &validatorService{
		availabilityStore: availabilityStore,
	}
}

type validatorService struct {
	availabilityStore *store.Availability
}

func (s *validatorService) ShardDistribution(ctx context.Context, erasureRoot crypto.Hash, shardIndex uint16) (bundleShard []byte, segmentShard [][]byte, justification [][]byte, err error) {
	//TODO implement me
	panic("implement me")
}

// AuditShardRequest gets the audit shards and justification from the availability store.
// this method will be later used by the auditors to request and reconstruct the work-package bundle and execute it to assess the correctness of the guarantee.
func (s *validatorService) AuditShardRequest(ctx context.Context, erasureRoot crypto.Hash, shardIndex uint16) (bundleShard []byte, justification [][]byte, err error) {
	bundleShard, err = s.availabilityStore.GetAuditShard(erasureRoot, shardIndex)
	if err != nil {
		return nil, nil, err
	}

	justification, err = s.availabilityStore.GetJustification(erasureRoot, shardIndex)
	if err != nil {
		return nil, nil, err
	}

	return bundleShard, justification, nil
}

// SegmentShardRequest gets the segments shards from the store and filters so only the shard segments with provided indexes are returned
// required for guarantors to reconstruct the segment shards from previous executions to be able to compute the work-packages and guarantee them.
// this variant the assurer does not provide any justification for the returned segment.
func (s *validatorService) SegmentShardRequest(ctx context.Context, erasureRoot crypto.Hash, shardIndex uint16, segmentIndexes []uint16) (segmentShards [][]byte, err error) {
	allSegmentsShards, err := s.availabilityStore.GetSegmentsShard(erasureRoot, shardIndex)
	if err != nil {
		return nil, err
	}
	for _, segmentIndex := range segmentIndexes {
		if len(allSegmentsShards) <= int(segmentIndex) {
			return nil, fmt.Errorf("segment shard segment index %d out of bounds", segmentIndex)
		}
		segmentShards = append(segmentShards, allSegmentsShards[segmentIndex])
	}
	return segmentShards, nil
}

// SegmentShardRequestJustification similar to SegmentShardRequest gets the segments shards and filters them,
// required for guarantors to reconstruct the segment shards from previous executions to be able to compute the work-packages and guarantee them.
// this variant the assurer provides the justification for the returned segment, allowing the guarantor to immediately asses the correctness of the response.
func (s *validatorService) SegmentShardRequestJustification(ctx context.Context, erasureRoot crypto.Hash, shardIndex uint16, segmentIndexes []uint16) (segmentShards [][]byte, justification [][][]byte, err error) {
	allSegmentsShards, err := s.availabilityStore.GetSegmentsShard(erasureRoot, shardIndex)
	if err != nil {
		return nil, nil, err
	}

	if len(segmentIndexes) == 0 || len(allSegmentsShards) == 0 {
		return nil, nil, nil
	}

	// build the segment index map to be able to filter only the needed segments
	segmentIndexesMap := make(map[uint16]struct{})
	for _, segmentIndex := range segmentIndexes {
		if len(allSegmentsShards) <= int(segmentIndex) {
			return nil, nil, fmt.Errorf("segment shard segment index %d out of bounds", segmentIndex)
		}
		segmentIndexesMap[segmentIndex] = struct{}{}
	}

	// return audit shard from store, required for computing the audit shard hash for the segment justification
	auditShard, err := s.availabilityStore.GetAuditShard(erasureRoot, shardIndex)
	if err != nil {
		return nil, nil, err
	}
	auditShardHash := crypto.HashData(auditShard)

	baseJustification, err := s.availabilityStore.GetJustification(erasureRoot, shardIndex)
	if err != nil {
		return nil, nil, err
	}

	for segmentIndex, segmentShard := range allSegmentsShards {
		_, ok := segmentIndexesMap[uint16(segmentIndex)]
		if !ok {
			continue
		}

		segmentShards = append(segmentShards, segmentShard)

		// compute the path from the segment shard root to the specific segment
		segmentShardJustification := binary_tree.ComputeTrace(allSegmentsShards, segmentIndex, crypto.HashData)

		// the justification for a shard is the path from the erasure root to the shard concatenated with the
		// path from the segment shard root to the specific segment
		// j ⌢ [b] ⌢ T(s, i, H)
		justification = append(justification, slices.Concat(baseJustification, [][]byte{auditShardHash[:]}, segmentShardJustification))
	}

	return segmentShards, justification, nil
}
