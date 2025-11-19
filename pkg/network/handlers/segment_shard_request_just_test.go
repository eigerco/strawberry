package handlers_test

import (
	"context"

	"github.com/eigerco/strawberry/internal/crypto/ed25519"

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

func TestSegmentShardRequestJustificationHandler(t *testing.T) {
	ctx := context.Background()
	mockStream := mocks.NewMockQuicStream()
	validatorSvc := validator.NewValidatorServiceMock()
	handler := handlers.NewSegmentShardRequestJustificationHandler(validatorSvc)
	peerKey, _, _ := ed25519.GenerateKey(nil)

	// test data
	erasureRoot := testutils.RandomHash(t)
	shardIndex := uint16(76)
	segmentIndexes := []uint16{0, 1, 2}
	expectedSegmentShard := [][]byte{
		{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12},
		{13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24},
		{23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34},
	}
	hash1 := testutils.RandomHash(t)
	hash2 := testutils.RandomHash(t)
	hash3 := testutils.RandomHash(t)
	hash4 := testutils.RandomHash(t)
	expectedJustification := [][][]byte{
		{hash1[:], hash2[:], append(hash3[:], hash4[:]...), expectedSegmentShard[0]},
		{hash1[:], hash2[:], append(hash3[:], hash4[:]...), expectedSegmentShard[1]},
		{hash1[:], hash2[:], append(hash3[:], hash4[:]...), expectedSegmentShard[2]},
	}
	expectedJustificationBytes := [][]byte{
		slices.Concat([]byte{0}, hash1[:], []byte{0}, hash2[:], []byte{1}, append(hash3[:], hash4[:]...), []byte{2}, expectedSegmentShard[0]),
		slices.Concat([]byte{0}, hash1[:], []byte{0}, hash2[:], []byte{1}, append(hash3[:], hash4[:]...), []byte{2}, expectedSegmentShard[1]),
		slices.Concat([]byte{0}, hash1[:], []byte{0}, hash2[:], []byte{1}, append(hash3[:], hash4[:]...), []byte{2}, expectedSegmentShard[2]),
	}

	// Prepare the message data
	req := handlers.ErasureRootShardAndSegmentIndexes{
		ErasureRoot:    erasureRoot,
		ShardIndex:     shardIndex,
		SegmentIndexes: segmentIndexes,
	}
	reqBytes, err := jam.Marshal(req)
	require.NoError(t, err)

	validatorSvc.On("SegmentShardRequestJustification", mock.Anything, erasureRoot, shardIndex, segmentIndexes).Return(expectedSegmentShard, expectedJustification, nil)
	mockTConn := mocks.NewMockTransportConn()

	mockTConn.On("OpenStream", ctx).Return(mockStream, nil)

	mockStream.On("Read", mock.Anything).
		Run(readBytes(le32encode(len(reqBytes)))).Return(4, nil).Once()
	mockStream.On("Read", mock.Anything).
		Run(readBytes(reqBytes)).Return(len(reqBytes), nil).Once()

	// segment shards message
	expectedSegmentShardBytes := slices.Concat(expectedSegmentShard...)
	mockStream.On("Write", le32encode(len(expectedSegmentShardBytes))).Return(4, nil).Once()
	mockStream.On("Write", expectedSegmentShardBytes).Return(len(expectedSegmentShardBytes), nil).Once()

	// justification messages
	for _, just := range expectedJustificationBytes {
		mockStream.On("Write", le32encode(len(just))).Return(4, nil).Once()
		mockStream.On("Write", just).Return(len(just), nil).Once()
	}

	// Setup for stream closure
	mockStream.On("Close").Return(nil).Once()

	// Execute
	err = handler.HandleStream(ctx, mockStream, peerKey)
	require.NoError(t, err)

	// Verify all expectations were met
	mockStream.AssertExpectations(t)
}

func TestSegmentShardRequestJustificationSender(t *testing.T) {
	ctx := context.Background()
	mockStream := mocks.NewMockQuicStream()
	sender := &handlers.SegmentShardRequestJustificationSender{}

	// test data
	erasureRoot := testutils.RandomHash(t)
	shardIndex := uint16(66)
	segmentIndexes := []uint16{0, 1, 2}
	expectedSegmentShard := [][]byte{
		{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12},
		{13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24},
		{23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34},
	}
	hash1 := testutils.RandomHash(t)
	hash2 := testutils.RandomHash(t)
	hash3 := testutils.RandomHash(t)
	hash4 := testutils.RandomHash(t)
	expectedJustification := [][][]byte{
		{hash1[:], hash2[:], append(hash3[:], hash4[:]...), expectedSegmentShard[0]},
		{hash1[:], hash2[:], append(hash3[:], hash4[:]...), expectedSegmentShard[1]},
		{hash1[:], hash2[:], append(hash3[:], hash4[:]...), expectedSegmentShard[2]},
	}
	expectedJustificationBytes := [][]byte{
		slices.Concat([]byte{0}, hash1[:], []byte{0}, hash2[:], []byte{1}, append(hash3[:], hash4[:]...), []byte{2}, expectedSegmentShard[0]),
		slices.Concat([]byte{0}, hash1[:], []byte{0}, hash2[:], []byte{1}, append(hash3[:], hash4[:]...), []byte{2}, expectedSegmentShard[1]),
		slices.Concat([]byte{0}, hash1[:], []byte{0}, hash2[:], []byte{1}, append(hash3[:], hash4[:]...), []byte{2}, expectedSegmentShard[2]),
	}

	mockTConn := mocks.NewMockTransportConn()

	mockTConn.On("OpenStream", ctx).Return(mockStream, nil)

	// Prepare the message data
	req := handlers.ErasureRootShardAndSegmentIndexes{
		ErasureRoot:    erasureRoot,
		ShardIndex:     shardIndex,
		SegmentIndexes: segmentIndexes,
	}
	reqBytes, err := jam.Marshal(req)
	require.NoError(t, err)

	// bundle shards message
	mockStream.On("Write", le32encode(len(reqBytes))).Return(4, nil).Once()
	mockStream.On("Write", reqBytes).Return(len(reqBytes), nil).Once()

	// segment shards message
	expectedSegmentShardBytes := slices.Concat(expectedSegmentShard...)
	mockStream.On("Read", mock.Anything).
		Run(readBytes(le32encode(len(expectedSegmentShardBytes)))).
		Return(4, nil).Once()
	mockStream.On("Read", mock.Anything).
		Run(readBytes(expectedSegmentShardBytes)).
		Return(len(expectedSegmentShardBytes), nil).Once()

	// justification message
	for _, just := range expectedJustificationBytes {
		mockStream.On("Read", mock.Anything).
			Run(readBytes(le32encode(len(just)))).
			Return(4, nil).Once()
		mockStream.On("Read", mock.Anything).
			Run(readBytes(just)).
			Return(len(just), nil).Once()

	}
	// Setup for stream closure
	mockStream.On("Close").Return(nil).Once()

	// Execute
	segmentShard, justification, err := sender.SegmentShardRequestJustification(ctx, mockStream, erasureRoot, shardIndex, segmentIndexes)
	require.NoError(t, err)
	require.Equal(t, expectedSegmentShard, segmentShard)
	require.Equal(t, expectedJustification, justification)

	// Verify all expectations were met
	mockStream.AssertExpectations(t)
}
