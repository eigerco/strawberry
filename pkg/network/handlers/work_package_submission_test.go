package handlers_test

import (
	"bytes"
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/eigerco/strawberry/internal/block"
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/work"
	"github.com/eigerco/strawberry/pkg/network/handlers"
	"github.com/eigerco/strawberry/pkg/network/handlers/testutils"
	"github.com/eigerco/strawberry/pkg/serialization/codec/jam"
)

type MockFetcher struct{}

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
	fakeStream := testutils.NewMockStream()
	submitter := &handlers.WorkPackageSubmitter{}

	coreIndex := uint16(1)

	extrinsics := []byte("extrinsic_data")

	coreIndexBytes, err := jam.Marshal(coreIndex)
	require.NoError(t, err)
	pkgBytes, err := jam.Marshal(pkg)
	require.NoError(t, err)

	expectedMsg1 := new(bytes.Buffer)
	err = handlers.WriteMessageWithContext(ctx, expectedMsg1, append(coreIndexBytes, pkgBytes...))
	require.NoError(t, err)

	expectedExtrinsics := new(bytes.Buffer)
	err = handlers.WriteMessageWithContext(ctx, expectedExtrinsics, extrinsics)
	require.NoError(t, err)

	err = submitter.SubmitWorkPackage(ctx, fakeStream, coreIndex, pkg, extrinsics)
	require.NoError(t, err)

	assert.Equal(t, expectedMsg1.Bytes(), fakeStream.Buffer.Next(expectedMsg1.Len()))
	assert.Equal(t, expectedExtrinsics.Bytes(), fakeStream.Buffer.Next(expectedExtrinsics.Len()))
	assert.True(t, fakeStream.CloseCalled)
}

func TestHandleWorkPackage(t *testing.T) {
	ctx := context.Background()
	fakeStream := testutils.NewMockStream()
	handler := handlers.NewWorkPackageSubmissionHandler(&MockFetcher{})

	coreIndex := uint16(1)
	extrinsics := []byte("extrinsic_data")

	coreIndexBytes, err := jam.Marshal(coreIndex)
	require.NoError(t, err)
	pkgBytes, err := jam.Marshal(pkg)
	require.NoError(t, err)

	msg1 := new(bytes.Buffer)
	err = handlers.WriteMessageWithContext(ctx, msg1, append(coreIndexBytes, pkgBytes...))
	require.NoError(t, err)

	msg2 := new(bytes.Buffer)
	err = handlers.WriteMessageWithContext(ctx, msg2, extrinsics)
	require.NoError(t, err)

	fakeStream.Buffer.Write(msg1.Bytes())
	fakeStream.Buffer.Write(msg2.Bytes())

	err = handler.HandleStream(ctx, fakeStream)
	require.NoError(t, err)

	assert.True(t, fakeStream.CloseCalled)
}
