package handlers_test

import (
	"context"

	"github.com/eigerco/strawberry/internal/crypto/ed25519"

	"encoding/binary"
	"slices"
	"testing"

	"github.com/eigerco/strawberry/internal/testutils"
	"github.com/eigerco/strawberry/internal/validator"
	"github.com/eigerco/strawberry/pkg/network/handlers"
	"github.com/eigerco/strawberry/pkg/network/mocks"
	"github.com/eigerco/strawberry/pkg/serialization/codec/jam"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestShardDistributionHandler(t *testing.T) {
	ctx := context.Background()
	mockStream := mocks.NewMockQuicStream()
	validatorSvc := validator.NewValidatorServiceMock()
	handler := handlers.NewShardDistributionHandler(validatorSvc)
	peerKey, _, _ := ed25519.GenerateKey(nil)

	// test data
	erasureRoot := testutils.RandomHash(t)
	shardIndex := uint16(4)
	expectedBundleShard := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
	expectedSegmentShard := [][]byte{
		{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12},
		{13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24},
	}

	hash1 := testutils.RandomHash(t)
	hash2 := testutils.RandomHash(t)

	expectedJustification := [][]byte{hash1[:], hash2[:], append(hash1[:], hash2[:]...)}

	// Prepare the message data
	req := handlers.ErasureRootAndShardIndex{
		ErasureRoot: erasureRoot,
		ShardIndex:  shardIndex,
	}
	reqBytes, err := jam.Marshal(req)
	require.NoError(t, err)

	validatorSvc.On("ShardDistribution", mock.Anything, mock.Anything, mock.Anything).Return(expectedBundleShard, expectedSegmentShard, expectedJustification, nil)
	mockTConn := mocks.NewMockTransportConn()

	mockTConn.On("OpenStream", ctx).Return(mockStream, nil)

	mockStream.On("Read", mock.Anything).
		Run(readBytes(le32encode(len(reqBytes)))).Return(4, nil)
	mockStream.On("Read", mock.Anything).
		Run(readBytes(reqBytes)).Return(len(reqBytes), nil)

	// bundle shards message
	mockStream.On("Write", le32encode(len(expectedBundleShard))).Return(4, nil).Once()
	mockStream.On("Write", expectedBundleShard).Return(len(expectedBundleShard), nil).Once()

	// segment shards message
	expectedSegmentShardBytes := slices.Concat(expectedSegmentShard...)
	mockStream.On("Write", le32encode(len(expectedSegmentShardBytes))).Return(4, nil).Once()
	mockStream.On("Write", expectedSegmentShardBytes).Return(len(expectedSegmentShardBytes), nil).Once()

	// justification message
	expectedJustificationBytes := slices.Concat([]byte{0}, hash1[:], []byte{0}, hash2[:], []byte{1}, hash1[:], hash2[:])
	mockStream.On("Write", le32encode(len(expectedJustificationBytes))).Return(4, nil).Once()
	mockStream.On("Write", expectedJustificationBytes).Return(len(expectedJustificationBytes), nil).Once()

	// Setup for stream closure
	mockStream.On("Close").Return(nil).Once()

	// Execute
	err = handler.HandleStream(ctx, mockStream, peerKey)
	require.NoError(t, err)

	// Verify all expectations were met
	mockStream.AssertExpectations(t)
}

func TestShardDistributionSender(t *testing.T) {
	ctx := context.Background()
	mockStream := mocks.NewMockQuicStream()
	validatorSvc := validator.NewValidatorServiceMock()
	sender := &handlers.ShardDistributionSender{}

	// test data
	erasureRoot := testutils.RandomHash(t)
	shardIndex := uint16(4)
	expectedBundleShard := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
	expectedSegmentShard := [][]byte{
		{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12},
		{13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24},
	}

	hash1 := testutils.RandomHash(t)
	hash2 := testutils.RandomHash(t)

	expectedJustification := [][]byte{hash1[:], hash2[:], append(hash1[:], hash2[:]...)}

	validatorSvc.On("ShardDistribution", mock.Anything, erasureRoot, shardIndex).Return(expectedBundleShard, expectedSegmentShard, expectedJustification, nil)
	mockTConn := mocks.NewMockTransportConn()

	mockTConn.On("OpenStream", ctx).Return(mockStream, nil)

	// Prepare the message data
	req := handlers.ErasureRootAndShardIndex{
		ErasureRoot: erasureRoot,
		ShardIndex:  shardIndex,
	}
	reqBytes, err := jam.Marshal(req)
	require.NoError(t, err)

	// bundle shards message
	mockStream.On("Write", le32encode(len(reqBytes))).Return(4, nil).Once()
	mockStream.On("Write", reqBytes).Return(len(reqBytes), nil).Once()

	// bundle shards message
	mockStream.On("Read", mock.Anything).
		Run(readBytes(le32encode(len(expectedBundleShard)))).
		Return(4, nil).Once()
	mockStream.On("Read", mock.Anything).Run(readBytes(expectedBundleShard)).
		Return(len(expectedBundleShard), nil).Once()

	// segment shards message
	expectedSegmentShardBytes := slices.Concat(expectedSegmentShard...)
	mockStream.On("Read", mock.Anything).
		Run(readBytes(le32encode(len(expectedSegmentShardBytes)))).
		Return(4, nil).Once()
	mockStream.On("Read", mock.Anything).
		Run(readBytes(expectedSegmentShardBytes)).
		Return(len(expectedSegmentShardBytes), nil).Once()

	// justification message
	expectedJustificationBytes := slices.Concat([]byte{0}, hash1[:], []byte{0}, hash2[:], []byte{1}, hash1[:], hash2[:])
	mockStream.On("Read", mock.Anything).
		Run(readBytes(le32encode(len(expectedJustificationBytes)))).
		Return(4, nil).Once()
	mockStream.On("Read", mock.Anything).
		Run(readBytes(expectedJustificationBytes)).
		Return(len(expectedJustificationBytes), nil).Once()

	// Setup for stream closure
	mockStream.On("Close").Return(nil).Once()

	// Execute
	bundleShard, segmentShard, justification, err := sender.ShardDistribution(ctx, mockStream, erasureRoot, shardIndex)
	require.NoError(t, err)
	require.Equal(t, expectedBundleShard, bundleShard)
	require.Equal(t, expectedSegmentShard, segmentShard)
	require.Equal(t, expectedJustification, justification)

	// Verify all expectations were met
	mockStream.AssertExpectations(t)
}

func readBytes(v []byte) func(args mock.Arguments) {
	return func(args mock.Arguments) {
		b := args.Get(0).([]byte)
		copy(b, v)
	}
}

func le32encode(v int) []byte {
	size := make([]byte, 4)
	binary.LittleEndian.PutUint32(size, uint32(v))
	return size
}
