package validator

import (
	"context"

	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/stretchr/testify/mock"
)

func NewValidatorServiceMock() *ValidatorServiceMock {
	return &ValidatorServiceMock{}
}

type ValidatorServiceMock struct {
	mock.Mock
}

func (v *ValidatorServiceMock) ShardDistribution(ctx context.Context, erasureRoot crypto.Hash, shardIndex uint16) (bundleShard []byte, segmentShard [][]byte, justification [][]byte, err error) {
	args := v.MethodCalled("ShardDistribution", ctx, erasureRoot, shardIndex)
	return args.Get(0).([]byte), args.Get(1).([][]byte), args.Get(2).([][]byte), args.Error(3)
}

func (v *ValidatorServiceMock) AuditShardRequest(ctx context.Context, erasureRoot crypto.Hash, shardIndex uint16) (bundleShard []byte, justification [][]byte, err error) {
	args := v.MethodCalled("AuditShardRequest", ctx, erasureRoot, shardIndex)
	return args.Get(0).([]byte), args.Get(1).([][]byte), args.Error(2)
}
