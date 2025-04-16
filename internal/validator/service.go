package validator

import (
	"context"

	"github.com/eigerco/strawberry/internal/crypto"
)

type ValidatorService interface {
	ShardDistribution(ctx context.Context, erasureRoot crypto.Hash, shardIndex uint16) (bundleShard []byte, segmentShard [][]byte, justification [][]byte, err error)
	AuditShardRequest(ctx context.Context, erasureRoot crypto.Hash, shardIndex uint16) (bundleShard []byte, justification [][]byte, err error)
	SegmentShardRequest(ctx context.Context, erasureRoot crypto.Hash, shardIndex uint16, segmentIndexes []uint16) (segmentShards [][]byte, err error)
}

func NewService() ValidatorService {
	return &validatorService{}
}

type validatorService struct{}

func (s *validatorService) ShardDistribution(ctx context.Context, erasureRoot crypto.Hash, shardIndex uint16) (bundleShard []byte, segmentShard [][]byte, justification [][]byte, err error) {
	//TODO implement me
	panic("implement me")
}

func (s *validatorService) AuditShardRequest(ctx context.Context, erasureRoot crypto.Hash, shardIndex uint16) (bundleShard []byte, justification [][]byte, err error) {
	//TODO implement me
	panic("implement me")
}

func (s *validatorService) SegmentShardRequest(ctx context.Context, erasureRoot crypto.Hash, shardIndex uint16, segmentIndexes []uint16) (segmentShards [][]byte, err error) {
	//TODO implement me
	panic("implement me")
}
