package validator

import (
	"context"

	"github.com/eigerco/strawberry/internal/crypto"
)

type ValidatorService interface {
	ShardDist(ctx context.Context, erasureRoot crypto.Hash, shardIndex uint16) (bundleShard []byte, segmentShard [][]byte, justification [][]byte, err error)
}

func NewService() ValidatorService {
	return &validatorService{}
}

type validatorService struct{}

func (s *validatorService) ShardDist(ctx context.Context, erasureRoot crypto.Hash, shardIndex uint16) (bundleShard []byte, segmentShard [][]byte, justification [][]byte, err error) {
	//TODO implement me
	panic("implement me")
}
