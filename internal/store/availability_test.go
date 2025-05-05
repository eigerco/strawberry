package store

import (
	"slices"
	"testing"

	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/testutils"
	"github.com/stretchr/testify/assert"
)

func TestMakeAvailabilityKey(t *testing.T) {
	key := makeAvailabilityKey(prefixAvailabilitySegmentsShard, crypto.Hash{}, 1)
	assert.Equal(t, []byte{prefixAvailabilitySegmentsShard, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0}, key)

	hash1 := testutils.RandomHash(t)
	key1 := makeAvailabilityKey(prefixAvailabilityAuditShard, hash1, 255)
	assert.Equal(t, slices.Concat([]byte{prefixAvailabilityAuditShard}, hash1[:], []byte{255, 0}), key1)
}
