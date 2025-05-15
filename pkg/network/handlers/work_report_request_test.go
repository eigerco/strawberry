package handlers_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"testing"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/eigerco/strawberry/internal/block"
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/store"
	"github.com/eigerco/strawberry/internal/testutils"
	"github.com/eigerco/strawberry/pkg/db/pebble"
	"github.com/eigerco/strawberry/pkg/network/handlers"
	"github.com/eigerco/strawberry/pkg/network/mocks"
	"github.com/eigerco/strawberry/pkg/serialization/codec/jam"
)

func TestWorkReportRequester_RequestWorkReport_Success(t *testing.T) {
	ctx := context.Background()
	stream := mocks.NewMockQuicStream()

	workReport := block.WorkReport{
		CoreIndex:         2,
		AuthGasUsed:       10,
		Output:            []byte("output"),
		SegmentRootLookup: make(map[crypto.Hash]crypto.Hash),
	}

	hash := testutils.RandomHash(t)

	reqBytes, err := jam.Marshal(hash)
	require.NoError(t, err)

	respBytes, err := jam.Marshal(workReport)
	require.NoError(t, err)

	// Write request
	stream.On("Write", mock.MatchedBy(func(data []byte) bool {
		return len(data) == 4
	})).Return(4, nil).Once()
	stream.On("Write", mock.MatchedBy(func(data []byte) bool {
		return len(data) == len(reqBytes)
	})).Return(len(reqBytes), nil).Once()

	// Read response
	stream.On("Read", mock.Anything).Run(func(args mock.Arguments) {
		copy(args.Get(0).([]byte), le32encode(len(respBytes)))
	}).Return(4, nil).Once()
	stream.On("Read", mock.Anything).Run(func(args mock.Arguments) {
		copy(args.Get(0).([]byte), respBytes)
	}).Return(len(respBytes), nil).Once()

	stream.On("Close").Return(nil).Once()

	requester := handlers.NewWorkReportRequester()
	got, err := requester.RequestWorkReport(ctx, stream, hash)
	require.NoError(t, err)
	require.Equal(t, &workReport, got)

	stream.AssertExpectations(t)
}

func TestWorkReportRequestHandler_HandleStream_Success(t *testing.T) {
	ctx := context.Background()
	stream := mocks.NewMockQuicStream()

	workReport := block.WorkReport{
		CoreIndex:   2,
		AuthGasUsed: 10,
		Output:      []byte("output"),
	}

	kvStore, err := pebble.NewKVStore()
	require.NoError(t, err)
	wrStore := store.NewWorkReport(kvStore)

	err = wrStore.PutWorkReport(workReport)
	require.NoError(t, err)

	handler := handlers.NewWorkReportRequestHandler(wrStore)

	peerPub, _, _ := ed25519.GenerateKey(nil)

	hash, err := workReport.Hash()
	require.NoError(t, err)

	lenPrefix, err := jam.Marshal(uint32(len(hash)))
	require.NoError(t, err)
	message := append(lenPrefix, hash[:]...)

	stream.On("Read", mock.Anything).Run(func(args mock.Arguments) {
		copy(args.Get(0).([]byte), message[:4])
	}).Return(4, nil).Once()

	stream.On("Read", mock.Anything).Run(func(args mock.Arguments) {
		copy(args.Get(0).([]byte), hash[:])
	}).Return(len(hash), nil).Once()

	respBody, err := jam.Marshal(workReport)
	require.NoError(t, err)

	stream.On("Write", mock.MatchedBy(func(data []byte) bool {
		return len(data) == 4 // length prefix
	})).Return(4, nil).Once()

	stream.On("Write", mock.MatchedBy(func(data []byte) bool {
		return bytes.Equal(data, respBody)
	})).Return(len(respBody), nil).Once()

	stream.On("Close").Return(nil).Once()

	require.NoError(t, handler.HandleStream(ctx, stream, peerPub))

	stream.AssertExpectations(t)
}
