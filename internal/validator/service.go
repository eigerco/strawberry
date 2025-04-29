package validator

import (
	"context"
	"fmt"
	"github.com/eigerco/strawberry/internal/merkle/binary_tree"
	"github.com/eigerco/strawberry/internal/store"
	"slices"

	"github.com/eigerco/strawberry/internal/crypto"
)

type ValidatorService interface {
	ShardDistribution(ctx context.Context, erasureRoot crypto.Hash, shardIndex uint16) (bundleShard []byte, segmentShard [][]byte, justification [][]byte, err error)
	AuditShardRequest(ctx context.Context, erasureRoot crypto.Hash, shardIndex uint16) (bundleShard []byte, justification [][]byte, err error)
	SegmentShardRequest(ctx context.Context, erasureRoot crypto.Hash, shardIndex uint16, segmentIndexes []uint16) (segmentShards [][]byte, err error)
	SegmentShardRequestJustification(ctx context.Context, erasureRoot crypto.Hash, shardIndex uint16, segmentIndexes []uint16) (segmentShards [][]byte, justification [][][]byte, err error)
}

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

func (s *validatorService) SegmentShardRequest(ctx context.Context, erasureRoot crypto.Hash, shardIndex uint16, segmentIndexes []uint16) (segmentShards [][]byte, err error) {
	allSegmentsShards, err := s.availabilityStore.GetSegmentsShard(erasureRoot, shardIndex)
	if err != nil {
		return nil, err
	}
	for _, shardIndex := range segmentIndexes {
		if len(allSegmentsShards) < int(shardIndex) {
			return nil, fmt.Errorf("segment shard index %d out of bounds", shardIndex)
		}
		segmentShards = append(segmentShards, allSegmentsShards[shardIndex])
	}
	return segmentShards, nil
}

func (s *validatorService) SegmentShardRequestJustification(ctx context.Context, erasureRoot crypto.Hash, shardIndex uint16, segmentIndexes []uint16) (segmentShards [][]byte, justification [][][]byte, err error) {
	segmentShards, err = s.availabilityStore.GetSegmentsShard(erasureRoot, shardIndex)
	if err != nil {
		return nil, nil, err
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
