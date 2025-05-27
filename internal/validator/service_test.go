package validator

import (
	"context"
	"testing"

	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/merkle/binary_tree"
	"github.com/eigerco/strawberry/internal/store"
	"github.com/eigerco/strawberry/internal/testutils"
	"github.com/eigerco/strawberry/pkg/db/pebble"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestShardDistribution(t *testing.T) {
	kv, err := pebble.NewKVStore()
	require.NoError(t, err)
	avStore := store.NewShards(kv)

	erasureRoot := testutils.RandomHash(t)
	shardIndex := uint16(1)
	bundleShard := []byte{9, 8, 7}
	segmentsShard := [][]byte{{1, 2, 3}, {4, 5, 6}, {7, 8, 9}}
	justHash1 := testutils.RandomHash(t)
	justHash2 := testutils.RandomHash(t)
	justHash3 := testutils.RandomHash(t)
	justification := [][]byte{justHash1[:], justHash2[:], justHash3[:]}

	err = avStore.PutShardsAndJustification(erasureRoot, shardIndex, bundleShard, segmentsShard, justification)
	require.NoError(t, err)

	svc := NewService(avStore)

	ctx := context.Background()
	actualBundleShard, actualSegmentShard, actualJustification, err := svc.ShardDistribution(ctx, erasureRoot, shardIndex)
	require.NoError(t, err)

	assert.Equal(t, segmentsShard, actualSegmentShard)
	assert.Equal(t, bundleShard, actualBundleShard)
	assert.Equal(t, justification, actualJustification)
}

func TestAuditShardRequest(t *testing.T) {
	kv, err := pebble.NewKVStore()
	require.NoError(t, err)
	avStore := store.NewShards(kv)

	erasureRoot := testutils.RandomHash(t)
	shardIndex := uint16(1)
	bundleShard := []byte{9, 8, 7}
	justHash1 := testutils.RandomHash(t)
	justHash2 := testutils.RandomHash(t)
	justHash3 := testutils.RandomHash(t)
	justification := [][]byte{justHash1[:], justHash2[:], justHash3[:]}

	err = avStore.PutShardsAndJustification(erasureRoot, shardIndex, bundleShard, nil, justification)
	require.NoError(t, err)

	svc := NewService(avStore)

	ctx := context.Background()
	actualBundleShard, actualJustification, err := svc.AuditShardRequest(ctx, erasureRoot, shardIndex)
	require.NoError(t, err)

	assert.Equal(t, bundleShard, actualBundleShard)
	assert.Equal(t, justification, actualJustification)
}

func TestSegmentShardRequest(t *testing.T) {
	kv, err := pebble.NewKVStore()
	require.NoError(t, err)
	avStore := store.NewShards(kv)

	erasureRoot := testutils.RandomHash(t)
	shardIndex := uint16(1)
	bundleShard := []byte{9, 8, 7}
	segmentsShard := [][]byte{{1, 2, 3}, {4, 5, 6}, {7, 8, 9}}
	justHash1 := testutils.RandomHash(t)
	justHash2 := testutils.RandomHash(t)
	justHash3 := testutils.RandomHash(t)
	baseJustification := [][]byte{justHash1[:], justHash2[:], justHash3[:]}

	err = avStore.PutShardsAndJustification(erasureRoot, shardIndex, bundleShard, segmentsShard, baseJustification)
	require.NoError(t, err)

	svc := NewService(avStore)

	ctx := context.Background()
	segmentsShards, err := svc.SegmentShardRequest(ctx, erasureRoot, shardIndex, []uint16{1, 2})
	require.NoError(t, err)

	assert.Equal(t, [][]byte{{4, 5, 6}, {7, 8, 9}}, segmentsShards)
}

func TestSegmentShardRequestJustification(t *testing.T) {
	kv, err := pebble.NewKVStore()
	require.NoError(t, err)
	avStore := store.NewShards(kv)

	erasureRoot := testutils.RandomHash(t)
	shardIndex := uint16(1)
	bundleShard := []byte{9, 8, 7}
	segmentsShards := [][]byte{{1, 2, 3}, {4, 5, 6}, {7, 8, 9}}
	justHash1 := testutils.RandomHash(t)
	justHash2 := testutils.RandomHash(t)
	justHash3 := testutils.RandomHash(t)
	baseJustification := [][]byte{justHash1[:], justHash2[:], justHash3[:]}

	ctx := context.Background()
	svc := NewService(avStore)

	err = avStore.PutShardsAndJustification(erasureRoot, shardIndex, bundleShard, nil, baseJustification)
	require.NoError(t, err)

	t.Run("zero segments shards stored", func(t *testing.T) {
		actualSegmentsShards, justification, err := svc.SegmentShardRequestJustification(ctx, erasureRoot, shardIndex, []uint16{})
		require.NoError(t, err)

		assert.Nil(t, actualSegmentsShards)
		assert.Nil(t, justification)
	})

	err = avStore.PutShardsAndJustification(erasureRoot, shardIndex, bundleShard, segmentsShards, baseJustification)
	require.NoError(t, err)

	t.Run("zero segments shards", func(t *testing.T) {
		actualSegmentsShards, justification, err := svc.SegmentShardRequestJustification(ctx, erasureRoot, shardIndex, []uint16{})
		require.NoError(t, err)

		assert.Nil(t, actualSegmentsShards)
		assert.Nil(t, justification)
	})

	t.Run("one segment shard", func(t *testing.T) {
		actualSegmentsShards, justification, err := svc.SegmentShardRequestJustification(ctx, erasureRoot, shardIndex, []uint16{1})
		require.NoError(t, err)

		assert.Equal(t, [][]byte{{4, 5, 6}}, actualSegmentsShards)
		bundleHash := crypto.HashData(bundleShard)
		segmentJust := binary_tree.ComputeTrace(segmentsShards, 1, crypto.HashData)
		expectedJust := append(baseJustification, append([][]byte{bundleHash[:]}, segmentJust...)...)
		assert.Equal(t, [][][]byte{expectedJust}, justification)
	})

	t.Run("two segments shards", func(t *testing.T) {
		actualSegmentsShards, justification, err := svc.SegmentShardRequestJustification(ctx, erasureRoot, shardIndex, []uint16{0, 1})
		require.NoError(t, err)

		assert.Equal(t, [][]byte{{1, 2, 3}, {4, 5, 6}}, actualSegmentsShards)
		bundleHash := crypto.HashData(bundleShard)

		segmentJust1 := binary_tree.ComputeTrace(segmentsShards, 0, crypto.HashData)
		expectedJust1 := append(baseJustification, append([][]byte{bundleHash[:]}, segmentJust1...)...)
		segmentJust2 := binary_tree.ComputeTrace(segmentsShards, 1, crypto.HashData)
		expectedJust2 := append(baseJustification, append([][]byte{bundleHash[:]}, segmentJust2...)...)
		assert.Equal(t, [][][]byte{expectedJust1, expectedJust2}, justification)
	})

	t.Run("all segments shards", func(t *testing.T) {
		actualSegmentsShards, justification, err := svc.SegmentShardRequestJustification(ctx, erasureRoot, shardIndex, []uint16{0, 1, 2})
		require.NoError(t, err)

		assert.Equal(t, segmentsShards, actualSegmentsShards)
		bundleHash := crypto.HashData(bundleShard)

		segmentJust1 := binary_tree.ComputeTrace(segmentsShards, 0, crypto.HashData)
		expectedJust1 := append(baseJustification, append([][]byte{bundleHash[:]}, segmentJust1...)...)
		segmentJust2 := binary_tree.ComputeTrace(segmentsShards, 1, crypto.HashData)
		expectedJust2 := append(baseJustification, append([][]byte{bundleHash[:]}, segmentJust2...)...)
		segmentJust3 := binary_tree.ComputeTrace(segmentsShards, 2, crypto.HashData)
		expectedJust3 := append(baseJustification, append([][]byte{bundleHash[:]}, segmentJust3...)...)
		assert.Equal(t, [][][]byte{expectedJust1, expectedJust2, expectedJust3}, justification)
	})
	t.Run("invalid segment shard index", func(t *testing.T) {
		_, _, err := svc.SegmentShardRequestJustification(ctx, erasureRoot, shardIndex, []uint16{3})
		require.ErrorContains(t, err, "segment shard segment index")
	})
}
