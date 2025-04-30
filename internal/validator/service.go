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

// AuditShardRequest gets the audit shards and justification from the availability store
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
// but also constructs the justification for each segment shard
func (s *validatorService) SegmentShardRequestJustification(ctx context.Context, erasureRoot crypto.Hash, shardIndex uint16, segmentIndexes []uint16) (segmentShards [][]byte, justification [][][]byte, err error) {
	allSegmentsShards, err := s.availabilityStore.GetSegmentsShard(erasureRoot, shardIndex)
	if err != nil {
		return nil, nil, err
	}
	for _, segmentIndex := range segmentIndexes {
		if len(allSegmentsShards) <= int(segmentIndex) {
			return nil, nil, fmt.Errorf("segment shard segment index %d out of bounds", segmentIndex)
		}
		segmentShards = append(segmentShards, allSegmentsShards[segmentIndex])
	}

	if len(segmentShards) == 0 {
		return nil, nil, nil
	}

	auditShard, err := s.availabilityStore.GetAuditShard(erasureRoot, shardIndex)
	if err != nil {
		return nil, nil, err
	}
	baseJustification, err := s.availabilityStore.GetJustification(erasureRoot, shardIndex)
	if err != nil {
		return nil, nil, err
	}

	for segmentIndex := range segmentShards {
		auditShardHash := crypto.HashData(auditShard)
		segmentShardJustification := binary_tree.ComputeTrace(segmentShards, segmentIndex, crypto.HashData)

		// j ⌢ [b] ⌢ T(s, i, H)
		justification = append(justification, slices.Concat(baseJustification, [][]byte{auditShardHash[:]}, segmentShardJustification))
	}

	return segmentShards, justification, nil
}
