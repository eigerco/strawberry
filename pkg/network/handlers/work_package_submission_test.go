package handlers_test

import (
	"context"
	"crypto/ed25519"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/eigerco/strawberry/internal/block"
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/work"
	"github.com/eigerco/strawberry/pkg/network/handlers"
	"github.com/eigerco/strawberry/pkg/network/mocks"
	"github.com/eigerco/strawberry/pkg/serialization/codec/jam"
)

type MockFetcher struct {
	mock.Mock
}

func (m *MockFetcher) FetchImportedSegment(hash crypto.Hash) ([]byte, error) {
	return []byte("mock segment data"), nil
}

var pkg = work.Package{
	AuthorizationToken: []byte("auth token"),
	AuthorizerService:  1,
	AuthCodeHash:       crypto.Hash{0x01},
	Parameterization:   []byte("parameters"),
	Context:            block.RefinementContext{},
	WorkItems: []work.Item{
		{
			ServiceId:          1,
			CodeHash:           crypto.Hash{0xAA},
			Payload:            []byte("payload data"),
			GasLimitRefine:     1000,
			GasLimitAccumulate: 2000,
			ImportedSegments: []work.ImportedSegment{
				{Hash: crypto.Hash{0x01}, Index: 0},
			},
			Extrinsics: []work.Extrinsic{
				{Hash: crypto.Hash{0x01}, Length: 12},
			},
			ExportedSegments: 2,
		},
	},
}

func TestSubmitWorkPackage(t *testing.T) {
	ctx := context.Background()
	mockStream := mocks.NewMockQuicStream()
	submitter := &handlers.WorkPackageSubmitter{}

	coreIndex := uint16(1)
	extrinsics := []byte("extrinsic_data")

	// Prepare expected data
	coreIndexBytes, err := jam.Marshal(coreIndex)
	require.NoError(t, err)
	pkgBytes, err := jam.Marshal(pkg)
	require.NoError(t, err)
	msg1 := append(coreIndexBytes, pkgBytes...)

	// Setup the mock to expect Write calls
	mockStream.On("Write", mock.MatchedBy(func(data []byte) bool {
		// Message 1: Contains length prefix for the combined message
		return len(data) >= 4 // length prefix (at least)
	})).Return(4, nil).Once()

	// Expect the actual message content write
	mockStream.On("Write", mock.MatchedBy(func(data []byte) bool {
		return len(data) > 0
	})).Return(len(msg1), nil).Once()

	mockStream.On("Write", mock.MatchedBy(func(data []byte) bool {
		return len(data) >= 4 // length prefix
	})).Return(4, nil).Once()

	mockStream.On("Write", mock.MatchedBy(func(data []byte) bool {
		return len(data) > 0
	})).Return(len(extrinsics), nil).Once()

	// Setup for stream closure
	mockStream.On("Close").Return(nil).Once()

	// Execute
	err = submitter.SubmitWorkPackage(ctx, mockStream, coreIndex, pkg, extrinsics)
	require.NoError(t, err)

	// Verify all expectations were met
	mockStream.AssertExpectations(t)
}

func TestHandleWorkPackage(t *testing.T) {
	ctx := context.Background()
	mockStream := mocks.NewMockQuicStream()
	handler := handlers.NewWorkPackageSubmissionHandler(&MockFetcher{})
	peerKey, _, _ := ed25519.GenerateKey(nil)

	// Prepare the message data
	coreIndex := uint16(1)
	coreIndexBytes, err := jam.Marshal(coreIndex)
	require.NoError(t, err)
	pkgBytes, err := jam.Marshal(pkg)
	require.NoError(t, err)
	msg1Content := append(coreIndexBytes, pkgBytes...)
	extrinsics := []byte("extrinsic_data")

	// Setup READ expectations for message 1 - length prefix followed by content
	mockStream.On("Read", mock.AnythingOfType("[]uint8")).
		Run(func(args mock.Arguments) {
			b := args.Get(0).([]byte)
			sizeBytes, err := jam.Marshal(uint32(len(msg1Content)))
			require.NoError(t, err)
			copy(b, sizeBytes)
		}).
		Return(4, nil).Once()

	// Message content
	mockStream.On("Read", mock.AnythingOfType("[]uint8")).
		Run(func(args mock.Arguments) {
			buffer := args.Get(0).([]byte)
			copy(buffer, msg1Content)
		}).
		Return(len(msg1Content), nil).Once()

	// Setup READ expectations for message 2 - length prefix followed by content
	mockStream.On("Read", mock.AnythingOfType("[]uint8")).
		Run(func(args mock.Arguments) {
			b := args.Get(0).([]byte)
			sizeBytes, err := jam.Marshal(uint32(len(extrinsics)))
			require.NoError(t, err)
			copy(b, sizeBytes)
		}).
		Return(4, nil).Once()

	// Extrinsics content
	mockStream.On("Read", mock.AnythingOfType("[]uint8")).
		Run(func(args mock.Arguments) {
			buffer := args.Get(0).([]byte)
			copy(buffer, extrinsics)
		}).
		Return(len(extrinsics), nil).Once()

	// Setup for stream closure
	mockStream.On("Close").Return(nil).Once()

	// Execute
	err = handler.HandleStream(ctx, mockStream, peerKey)
	require.NoError(t, err)

	// Verify all expectations were met
	mockStream.AssertExpectations(t)
}

func TestSubmitWorkPackage_Success(t *testing.T) {
	mockStream := mocks.NewMockQuicStream()
	coreIndex := uint16(5)
	extrinsics := []byte("extrinsics data")

	// Setup mock write expectations - for simplicity, just expect any Write calls and return success
	mockStream.On("Write", mock.Anything).Return(4, nil).Once()               // size of message 1
	mockStream.On("Write", mock.Anything).Return(10, nil).Once()              // content of message 1
	mockStream.On("Write", mock.Anything).Return(4, nil).Once()               // size of message 2
	mockStream.On("Write", mock.Anything).Return(len(extrinsics), nil).Once() // content of message 2

	// Setup stream close expectation
	mockStream.On("Close").Return(nil)

	submitter := &handlers.WorkPackageSubmitter{}
	ctx := context.Background()
	err := submitter.SubmitWorkPackage(ctx, mockStream, coreIndex, pkg, extrinsics)

	assert.NoError(t, err)
	mockStream.AssertExpectations(t)
}

func TestSubmitWorkPackage_WriteFailure(t *testing.T) {
	mockStream := mocks.NewMockQuicStream()
	coreIndex := uint16(5)
	extrinsics := []byte("extrinsics data")

	// Setup mock to fail on write
	mockStream.On("Write", mock.Anything).Return(0, errors.New("write error"))

	submitter := &handlers.WorkPackageSubmitter{}
	ctx := context.Background()
	err := submitter.SubmitWorkPackage(ctx, mockStream, coreIndex, pkg, extrinsics)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to write message 1")
	mockStream.AssertExpectations(t)
}

func TestSubmitWorkPackage_SecondWriteFailure(t *testing.T) {
	mockStream := mocks.NewMockQuicStream()
	coreIndex := uint16(5)
	extrinsics := []byte("extrinsics data")

	// Setup mock to succeed on first message but fail on second
	mockStream.On("Write", mock.Anything).Return(4, nil).Once()                       // size of message 1 - success
	mockStream.On("Write", mock.Anything).Return(10, nil).Once()                      // content of message 1 - success
	mockStream.On("Write", mock.Anything).Return(0, errors.New("write error")).Once() // size of message 2 - fail

	submitter := &handlers.WorkPackageSubmitter{}
	ctx := context.Background()
	err := submitter.SubmitWorkPackage(ctx, mockStream, coreIndex, pkg, extrinsics)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to write message 2")
	mockStream.AssertExpectations(t)
}

func TestSubmitWorkPackage_CloseFailure(t *testing.T) {
	mockStream := mocks.NewMockQuicStream()
	coreIndex := uint16(5)
	extrinsics := []byte("extrinsics data")

	// Setup mock write expectations - all succeed
	mockStream.On("Write", mock.Anything).Return(4, nil).Once()               // size of message 1
	mockStream.On("Write", mock.Anything).Return(10, nil).Once()              // content of message 1
	mockStream.On("Write", mock.Anything).Return(4, nil).Once()               // size of message 2
	mockStream.On("Write", mock.Anything).Return(len(extrinsics), nil).Once() // content of message 2

	// But closing fails
	mockStream.On("Close").Return(errors.New("close error"))

	submitter := &handlers.WorkPackageSubmitter{}
	ctx := context.Background()
	err := submitter.SubmitWorkPackage(ctx, mockStream, coreIndex, pkg, extrinsics)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to close stream")
	mockStream.AssertExpectations(t)
}

func TestHandleStream_Success(t *testing.T) {
	mockStream := mocks.NewMockQuicStream()
	mockFetcher := &MockFetcher{}
	coreIndex := uint16(5)
	peerKey, _, _ := ed25519.GenerateKey(nil)

	coreIndexBytes, err := jam.Marshal(coreIndex)
	require.NoError(t, err)
	pkgBytes, err := jam.Marshal(pkg)
	require.NoError(t, err)
	msg1Content := append(coreIndexBytes, pkgBytes...)

	// Setup mock to read message 1
	mockStream.On("Read", mock.Anything).Run(func(args mock.Arguments) {
		b := args.Get(0).([]byte)
		sizeBytes, err := jam.Marshal(uint32(len(msg1Content)))
		require.NoError(t, err)
		copy(b, sizeBytes)
	}).Return(4, nil).Once()

	mockStream.On("Read", mock.Anything).Run(func(args mock.Arguments) {
		b := args.Get(0).([]byte)
		copy(b, msg1Content)
	}).Return(len(msg1Content), nil).Once()

	// Setup mock to read message 2
	extrinsics := []byte("extrinsics data")
	mockStream.On("Read", mock.Anything).Run(func(args mock.Arguments) {
		b := args.Get(0).([]byte)
		sizeBytes, err := jam.Marshal(uint32(len(extrinsics)))
		require.NoError(t, err)
		copy(b, sizeBytes)
	}).Return(4, nil).Once()

	mockStream.On("Read", mock.Anything).Run(func(args mock.Arguments) {
		b := args.Get(0).([]byte)
		copy(b, extrinsics)
	}).Return(len(extrinsics), nil).Once()
	// Setup stream close expectation
	mockStream.On("Close").Return(nil)

	handler := handlers.NewWorkPackageSubmissionHandler(&MockFetcher{})
	ctx := context.Background()
	err = handler.HandleStream(ctx, mockStream, peerKey)

	assert.NoError(t, err)
	mockStream.AssertExpectations(t)
	mockFetcher.AssertExpectations(t)
}
