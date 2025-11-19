//go:build integration

package d3l_test

import (
	"context"

	"crypto/rand"
	"errors"
	"testing"

	"github.com/eigerco/strawberry/internal/crypto/ed25519"

	"github.com/eigerco/strawberry/internal/common"
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/d3l"
	"github.com/eigerco/strawberry/internal/erasurecoding"
	"github.com/eigerco/strawberry/internal/testutils"
	"github.com/eigerco/strawberry/internal/work"
	"github.com/eigerco/strawberry/pkg/network/peer"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

type assurerClientMock struct {
	mock.Mock
}

func (a *assurerClientMock) GetAllPeers() []*peer.Peer {
	args := a.MethodCalled("GetAllPeers")
	return args.Get(0).([]*peer.Peer)
}

func (a *assurerClientMock) SegmentShardRequestSend(ctx context.Context, peerKey ed25519.PublicKey, erasureRoot crypto.Hash, shardIndex uint16, segmentIndexes []uint16) (segmentShards [][]byte, err error) {
	args := a.MethodCalled("SegmentShardRequestSend", ctx, peerKey, erasureRoot, shardIndex, segmentIndexes)
	return args.Get(0).([][]byte), args.Error(1)
}

func TestNewSegmentsFetcher(t *testing.T) {
	assurers := make([]*peer.Peer, common.NumberOfValidators)
	for i := range assurers {
		validatorIndex := uint16(i)
		pub, _, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		assurers[i] = &peer.Peer{
			Ed25519Key:     pub,
			ValidatorIndex: &validatorIndex,
		}
	}

	segment1 := buildSegment(t, "segment 1")
	segment2 := buildSegment(t, "segment 2")

	segmentRoot := testutils.RandomHash(t)
	erasureRoot := testutils.RandomHash(t)
	segmentIndexes := []uint16{0, 1}
	ctx := context.Background()

	segment1Shards, err := erasurecoding.Encode(segment1[:])
	require.NoError(t, err)

	segment2Shards, err := erasurecoding.Encode(segment2[:])
	require.NoError(t, err)

	t.Run("success all valid assurers", func(t *testing.T) {
		assurerClient := new(assurerClientMock)
		assurerClient.On("GetAllPeers").Return(assurers)
		for i, assurer := range assurers[:common.ErasureCodingOriginalShards] {
			assurerClient.On("SegmentShardRequestSend", ctx, assurer.Ed25519Key, erasureRoot, *assurer.ValidatorIndex, segmentIndexes).
				Return([][]byte{
					segment1Shards[i],
					segment2Shards[i],
				}, nil)
		}

		sf := d3l.NewSegmentsFetcher(assurerClient, map[crypto.Hash]crypto.Hash{
			segmentRoot: erasureRoot,
		})

		reconstructedSegments, err := sf.Fetch(ctx, segmentRoot, segmentIndexes...)
		require.NoError(t, err)
		require.Len(t, reconstructedSegments, 2)

		assert.Equal(t, reconstructedSegments[0], segment1)
		assert.Equal(t, reconstructedSegments[1], segment2)
		assurerClient.AssertExpectations(t)
	})
	t.Run("success some valid assurers", func(t *testing.T) {
		assurerClient := new(assurerClientMock)
		assurerClient.On("GetAllPeers").Return(assurers)
		for i, assurer := range assurers[:common.ErasureCodingOriginalShards*2] {
			if i%2 == 0 {
				assurerClient.On("SegmentShardRequestSend", mock.Anything, assurer.Ed25519Key, erasureRoot, *assurer.ValidatorIndex, segmentIndexes).
					Return([][]byte{nil}, errors.New("cannot get the shards"))
				continue
			}
			assurerClient.On("SegmentShardRequestSend", ctx, assurer.Ed25519Key, erasureRoot, *assurer.ValidatorIndex, segmentIndexes).
				Return([][]byte{
					segment1Shards[i/2],
					segment2Shards[i/2],
				}, nil)
		}

		sf := d3l.NewSegmentsFetcher(assurerClient, map[crypto.Hash]crypto.Hash{
			segmentRoot: erasureRoot,
		})

		reconstructedSegments, err := sf.Fetch(ctx, segmentRoot, segmentIndexes...)
		require.NoError(t, err)
		require.Len(t, reconstructedSegments, 2)

		assert.Equal(t, segment1, reconstructedSegments[0])
		assert.Equal(t, segment2, reconstructedSegments[1])
		assurerClient.AssertExpectations(t)
	})
	t.Run("no erasure root", func(t *testing.T) {
		assurerClient := new(assurerClientMock)
		sf2 := d3l.NewSegmentsFetcher(assurerClient, map[crypto.Hash]crypto.Hash{})
		_, err := sf2.Fetch(ctx, segmentRoot, segmentIndexes...)
		assert.ErrorContains(t, err, "no erasure root for segment-root")
		assurerClient.AssertExpectations(t)
	})
	t.Run("no valid assurers", func(t *testing.T) {
		assurerClient := new(assurerClientMock)
		assurerClient.On("GetAllPeers").Return(assurers)
		for _, assurer := range assurers {
			assurerClient.On("SegmentShardRequestSend", ctx, assurer.Ed25519Key, erasureRoot, *assurer.ValidatorIndex, segmentIndexes).
				Return([][]byte{nil}, errors.New("cannot get the shards"))
		}

		sf := d3l.NewSegmentsFetcher(assurerClient, map[crypto.Hash]crypto.Hash{
			segmentRoot: erasureRoot,
		})

		_, err := sf.Fetch(ctx, segmentRoot, segmentIndexes...)
		require.ErrorContains(t, err, "couldn't get enough shards for segment")
		assurerClient.AssertExpectations(t)
	})
}

func buildSegment(t *testing.T, data string) work.Segment {
	require.Less(t, len(data), common.SizeOfSegment)
	seg := work.Segment{}
	copy(seg[:], data)
	return seg
}
