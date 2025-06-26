package handlers_test

import (
	"context"
	"crypto/ed25519"
	"errors"
	"testing"

	"github.com/eigerco/strawberry/internal/state/serialization/statekey"
	"github.com/eigerco/strawberry/internal/validator"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/eigerco/strawberry/internal/block"
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/jamtime"
	"github.com/eigerco/strawberry/internal/service"
	"github.com/eigerco/strawberry/internal/state"
	"github.com/eigerco/strawberry/internal/store"
	"github.com/eigerco/strawberry/internal/work"
	"github.com/eigerco/strawberry/internal/work/results"
	"github.com/eigerco/strawberry/pkg/db/pebble"
	"github.com/eigerco/strawberry/pkg/network/handlers"
	"github.com/eigerco/strawberry/pkg/network/mocks"
	"github.com/eigerco/strawberry/pkg/network/peer"
	"github.com/eigerco/strawberry/pkg/network/protocol"
	"github.com/eigerco/strawberry/pkg/serialization/codec/jam"
)

type MockFetcher struct {
	mock.Mock
}

func (m *MockFetcher) Fetch(ctx context.Context, segmentRoot crypto.Hash, segmentIndexes ...uint16) ([]work.Segment, error) {
	seg := work.Segment{}
	copy(seg[:], "mock segment data")
	return []work.Segment{seg}, nil
}

var pkg = work.Package{
	AuthorizationToken: []byte("auth token"),
	AuthorizerService:  1,
	AuthCodeHash:       crypto.HashData([]byte("mock-auth-code")),
	Parameterization:   []byte("parameters"),
	Context:            block.RefinementContext{},
	WorkItems: []work.Item{
		{
			ServiceId:          1,
			CodeHash:           crypto.Hash{0xAA},
			Payload:            []byte("payload data"),
			GasLimitRefine:     1000,
			GasLimitAccumulate: 2000,
			ImportedSegments:   []work.ImportedSegment{}, // TODO add proper imported segments
			Extrinsics:         []work.Extrinsic{},       // TODO add proper extrinsics
			ExportedSegments:   2,
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
	coreIndex := uint16(1)

	pool := state.CoreAuthorizersPool{}
	pool[coreIndex] = []crypto.Hash{pkg.AuthCodeHash}
	currentState := state.State{
		Services:            getServiceState(t),
		CoreAuthorizersPool: pool,
	}

	peerKey, prv, _ := ed25519.GenerateKey(nil)
	kvStore, err := pebble.NewKVStore()
	require.NoError(t, err)
	s := store.NewWorkReport(kvStore)

	validatorMock := validator.NewValidatorServiceMock()
	validatorMock.On("StoreAllShards", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil)
	workPackageSharer := handlers.NewWorkReportGuarantor(coreIndex, prv, mockAuthorizationInvoker{}, mockRefineInvoker{}, currentState, peer.NewPeerSet(), s, nil, nil, nil, validatorMock, make(work.SegmentRootLookup))
	handler := handlers.NewWorkPackageSubmissionHandler(&MockFetcher{}, workPackageSharer, make(work.SegmentRootLookup))

	// Prepare the message data
	coreIndexBytes, err := jam.Marshal(coreIndex)
	require.NoError(t, err)
	pkgBytes, err := jam.Marshal(pkg)
	require.NoError(t, err)
	msg1Content := append(coreIndexBytes, pkgBytes...)
	extrinsics := []byte("extrinsic_data")

	mockTConn := mocks.NewMockTransportConn()
	registry := protocol.NewJAMNPRegistry()

	conn := protocol.NewProtocolConn(mockTConn, registry)

	validatorIndex := uint16(1)
	mockPeer := &peer.Peer{
		ProtoConn:      conn,
		ValidatorIndex: &validatorIndex,
		Ed25519Key:     peerKey,
	}

	mockTConn.On("OpenStream", ctx).Return(mockStream, nil)
	mockStream.On("Write", mock.Anything).Return(1, nil)

	mockStream.On("Close").Return(nil).Once()

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

	segmentRootLookup := make(work.SegmentRootLookup)

	builder, err := work.NewPackageBundleBuilder(pkg, segmentRootLookup, make(map[crypto.Hash][]work.Segment), []byte{})
	require.NoError(t, err)

	bundle, err := builder.Build()
	require.NoError(t, err)

	shards, workReport, err := results.ProduceWorkReport(mockRefineInvoker{}, getServiceState(t), []byte("Authorized"), coreIndex, bundle, segmentRootLookup)
	require.NoError(t, err)
	assert.NotNil(t, shards)

	h, err := workReport.Hash()
	require.NoError(t, err)

	signature := ed25519.Sign(prv, h[:])

	response := struct {
		WorkReportHash crypto.Hash
		Signature      crypto.Ed25519Signature
	}{
		WorkReportHash: h,
		Signature:      crypto.Ed25519Signature(signature),
	}

	responseBytes, err := jam.Marshal(response)
	require.NoError(t, err)

	mockStream.On("Read", mock.Anything).Run(func(args mock.Arguments) {
		b := args.Get(0).([]byte)
		sizeBytes, err := jam.Marshal(uint32(len(responseBytes)))
		require.NoError(t, err)
		copy(b, sizeBytes)
	}).Return(4, nil).Once()

	mockStream.On("Read", mock.Anything).Run(func(args mock.Arguments) {
		b := args.Get(0).([]byte)
		copy(b, responseBytes)
	}).Return(len(responseBytes), nil).Once()

	// Setup for stream closure
	mockStream.On("Close").Return(nil).Once()

	workPackageSharer.SetGuarantors([]*peer.Peer{mockPeer})

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
	ctx := context.Background()
	mockStream := mocks.NewMockQuicStream()
	mockFetcher := &MockFetcher{}
	coreIndex := uint16(5)
	peerKey, prv, _ := ed25519.GenerateKey(nil)

	pool := state.CoreAuthorizersPool{}
	pool[coreIndex] = []crypto.Hash{pkg.AuthCodeHash, crypto.HashData([]byte("another hash"))}
	currentState := state.State{
		Services:            getServiceState(t),
		CoreAuthorizersPool: pool,
	}

	kvStore, err := pebble.NewKVStore()
	require.NoError(t, err)
	s := store.NewWorkReport(kvStore)

	validatorMock := validator.NewValidatorServiceMock()
	validatorMock.On("StoreAllShards", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil)
	workPackageSharer := handlers.NewWorkReportGuarantor(coreIndex, prv, mockAuthorizationInvoker{}, mockRefineInvoker{}, currentState, peer.NewPeerSet(), s, nil, nil, nil, validatorMock, make(work.SegmentRootLookup))

	coreIndexBytes, err := jam.Marshal(coreIndex)
	require.NoError(t, err)
	pkgBytes, err := jam.Marshal(pkg)
	require.NoError(t, err)
	msg1Content := append(coreIndexBytes, pkgBytes...)

	mockTConn := mocks.NewMockTransportConn()
	registry := protocol.NewJAMNPRegistry()

	conn := protocol.NewProtocolConn(mockTConn, registry)

	validatorIndex := uint16(1)
	mockPeer := &peer.Peer{
		ProtoConn:      conn,
		ValidatorIndex: &validatorIndex,
		Ed25519Key:     peerKey,
	}

	mockTConn.On("OpenStream", ctx).Return(mockStream, nil)
	mockStream.On("Write", mock.Anything).Return(1, nil)

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

	segmentRootLookup := make(map[crypto.Hash]crypto.Hash)
	builder, err := work.NewPackageBundleBuilder(pkg, segmentRootLookup, make(map[crypto.Hash][]work.Segment), []byte{})
	require.NoError(t, err)

	bundle, err := builder.Build()
	require.NoError(t, err)

	shards, workReport, err := results.ProduceWorkReport(mockRefineInvoker{}, getServiceState(t), []byte("Authorized"), coreIndex, bundle, segmentRootLookup)
	require.NoError(t, err)
	assert.NotNil(t, shards)

	h, err := workReport.Hash()
	require.NoError(t, err)

	signature := ed25519.Sign(prv, h[:])

	response := struct {
		WorkReportHash crypto.Hash
		Signature      crypto.Ed25519Signature
	}{
		WorkReportHash: h,
		Signature:      crypto.Ed25519Signature(signature),
	}

	responseBytes, err := jam.Marshal(response)
	require.NoError(t, err)

	mockStream.On("Read", mock.Anything).Run(func(args mock.Arguments) {
		b := args.Get(0).([]byte)
		sizeBytes, err := jam.Marshal(uint32(len(responseBytes)))
		require.NoError(t, err)
		copy(b, sizeBytes)
	}).Return(4, nil).Once()

	mockStream.On("Read", mock.Anything).Run(func(args mock.Arguments) {
		b := args.Get(0).([]byte)
		copy(b, responseBytes)
	}).Return(len(responseBytes), nil).Once()

	// Setup stream close expectation
	mockStream.On("Close").Return(nil)

	workPackageSharer.SetGuarantors([]*peer.Peer{mockPeer})

	handler := handlers.NewWorkPackageSubmissionHandler(mockFetcher, workPackageSharer, make(work.SegmentRootLookup))
	err = handler.HandleStream(ctx, mockStream, peerKey)

	assert.NoError(t, err)
	mockStream.AssertExpectations(t)
	mockFetcher.AssertExpectations(t)
}

type mockAuthorizationInvoker struct{}

func (m mockAuthorizationInvoker) InvokePVM(workPackage work.Package, coreIndex uint16) ([]byte, error) {
	return []byte("Authorized"), nil
}

type mockRefineInvoker struct{}

func (m mockRefineInvoker) InvokePVM(
	itemIndex uint32,
	workPackage work.Package,
	authorizerHashOutput []byte,
	importedSegments []work.Segment,
	exportOffset uint64,
) ([]byte, []work.Segment, uint64, error) {
	out := []byte("RefineOutput")
	exported := []work.Segment{
		{},
	}
	return out, exported, 0, nil
}

func getServiceState(t *testing.T) service.ServiceState {
	authCodeHash := pkg.AuthCodeHash
	timeslot := jamtime.Timeslot(0)

	sa := service.ServiceAccount{
		PreimageLookup: map[crypto.Hash][]byte{
			authCodeHash: pkg.AuthorizationToken,
		},
	}

	k, err := statekey.NewPreimageMeta(block.ServiceId(1), authCodeHash, uint32(len(pkg.AuthorizationToken)))
	require.NoError(t, err)

	err = sa.InsertPreimageMeta(k, uint64(len(pkg.AuthorizationToken)), service.PreimageHistoricalTimeslots{timeslot})
	require.NoError(t, err)

	services := make(service.ServiceState)
	services[1] = sa

	return services
}
