package handlers_test

import (
	"context"
	"crypto/ed25519"
	"testing"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/eigerco/strawberry/internal/block"
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/service"
	"github.com/eigerco/strawberry/internal/work"
	"github.com/eigerco/strawberry/pkg/network/handlers"
	"github.com/eigerco/strawberry/pkg/network/mocks"
	"github.com/eigerco/strawberry/pkg/serialization/codec/jam"
)

func TestHandleSharingStream_Success(t *testing.T) {
	ctx := context.Background()
	mockStream := mocks.NewMockQuicStream()
	peerKey, privKey, _ := ed25519.GenerateKey(nil)

	pkg := work.Package{
		AuthorizationToken: []byte("auth-token"),
		AuthorizerService:  1,
		AuthCodeHash:       crypto.HashData([]byte("auth-token")),
		Parameterization:   []byte("params"),
		WorkItems: []work.Item{
			{
				ServiceId:          1,
				Payload:            []byte("data"),
				GasLimitRefine:     1000,
				GasLimitAccumulate: 1000,
				ExportedSegments:   1,
			},
		},
	}

	bundle := work.PackageBundle{
		Package:    pkg,
		Extrinsics: []byte("extrinsics"),
	}

	coreIndex := uint16(1)
	var rootMappings []handlers.SegmentRootMapping
	coreIndexBytes, err := jam.Marshal(coreIndex)
	require.NoError(t, err)
	mappings, err := jam.Marshal(rootMappings)
	require.NoError(t, err)
	msg1 := append(coreIndexBytes, mappings...)

	msg2, err := jam.Marshal(bundle)
	require.NoError(t, err)

	mockStream.On("Read", mock.Anything).Run(func(args mock.Arguments) {
		b := args.Get(0).([]byte)
		lenBytes, _ := jam.Marshal(uint32(len(msg1)))
		copy(b, lenBytes)
	}).Return(4, nil).Once()

	mockStream.On("Read", mock.Anything).Run(func(args mock.Arguments) {
		copy(args.Get(0).([]byte), msg1)
	}).Return(len(msg1), nil).Once()

	mockStream.On("Read", mock.Anything).Run(func(args mock.Arguments) {
		lenBytes, _ := jam.Marshal(uint32(len(msg2)))
		copy(args.Get(0).([]byte), lenBytes)
	}).Return(4, nil).Once()

	mockStream.On("Read", mock.Anything).Run(func(args mock.Arguments) {
		copy(args.Get(0).([]byte), msg2)
	}).Return(len(msg2), nil).Once()

	mockStream.On("Write", mock.Anything).Return(1, nil).Once()

	var writtenResponse []byte
	mockStream.On("Write", mock.Anything).Run(func(args mock.Arguments) {
		writtenResponse = args.Get(0).([]byte)
	}).Return(64, nil).Once()

	mockStream.On("Close").Return(nil).Once()

	authCode := pkg.AuthorizationToken
	authCodeHash := pkg.AuthCodeHash
	serviceState := service.ServiceState{
		block.ServiceId(pkg.AuthorizerService): service.ServiceAccount{
			PreimageLookup: map[crypto.Hash][]byte{
				authCodeHash: authCode,
			},
			PreimageMeta: map[service.PreImageMetaKey]service.PreimageHistoricalTimeslots{
				{
					Hash:   authCodeHash,
					Length: service.PreimageLength(len(authCode)),
				}: {pkg.Context.LookupAnchor.Timeslot},
			},
		},
	}

	handler := handlers.NewWorkPackageSharingHandler(
		mockAuthorizationInvoker{},
		mockRefineInvoker{},
		privKey,
		serviceState,
	)

	handler.SetCurrentCore(coreIndex)

	err = handler.HandleStream(ctx, mockStream, peerKey)
	require.NoError(t, err)

	var response struct {
		WorkReportHash crypto.Hash
		Signature      []byte
	}
	err = jam.Unmarshal(writtenResponse, &response)
	require.NoError(t, err)

	require.Len(t, response.Signature, ed25519.SignatureSize)
	require.NotEmpty(t, response.WorkReportHash)

	valid := ed25519.Verify(peerKey, response.WorkReportHash[:], response.Signature)
	require.True(t, valid, "Signature must be valid")

	mockStream.AssertExpectations(t)
}
