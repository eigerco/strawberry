package handlers_test

import (
	"context"
	"crypto/ed25519"
	"testing"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/eigerco/strawberry/internal/block"
	"github.com/eigerco/strawberry/internal/testutils"
	"github.com/eigerco/strawberry/pkg/network/handlers"
	"github.com/eigerco/strawberry/pkg/network/mocks"
	"github.com/eigerco/strawberry/pkg/serialization/codec/jam"
)

func TestWorkReportDistribution_HandleStream_Success(t *testing.T) {
	ctx := context.Background()
	stream := mocks.NewMockQuicStream()

	handler := handlers.NewWorkReportDistributionHandler()
	peerPub, _, _ := ed25519.GenerateKey(nil)

	g := block.Guarantee{
		Timeslot: 123,
		WorkReport: block.WorkReport{
			CoreIndex: 7,
		},
		Credentials: []block.CredentialSignature{
			{
				ValidatorIndex: 10,
				Signature:      testutils.RandomEd25519Signature(t),
			},
		},
	}

	raw, err := jam.Marshal(g)
	require.NoError(t, err)

	lenPrefix, err := jam.Marshal(uint32(len(raw)))
	require.NoError(t, err)
	message := append(lenPrefix, raw...)

	stream.On("Read", mock.Anything).Run(func(args mock.Arguments) {
		copy(args.Get(0).([]byte), message[:4])
	}).Return(4, nil).Once()

	stream.On("Read", mock.Anything).Run(func(args mock.Arguments) {
		copy(args.Get(0).([]byte), message[4:])
	}).Return(len(raw), nil).Once()

	stream.On("Close").Return(nil).Once()

	require.NoError(t, handler.HandleStream(ctx, stream, peerPub))
	stream.AssertExpectations(t)
}
