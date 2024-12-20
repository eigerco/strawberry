package reedsolomon

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/eigerco/strawberry/internal/testutils"
	"github.com/stretchr/testify/require"
	"golang.org/x/exp/rand"
)

func TestRoundTrip(t *testing.T) {
	jsonData, err := os.ReadFile("vectors/initial.json")
	require.NoError(t, err)

	tv := TestVector{}
	err = json.Unmarshal(jsonData, &tv)
	require.NoError(t, err)

	data := testutils.MustFromHex(t, tv.Data)

	rs, err := New(342, 681)
	require.NoError(t, err)

	shards, err := rs.Chunk(data)
	require.NoError(t, err)

	err = rs.Encode(shards)
	if err != nil {
		require.NoError(t, err)
	}

	// Compare our shards against the test vector shards.
	for i, shard := range tv.Segment.Segments[0].SegmentEC {
		require.Equal(t, hex.EncodeToString(shards[i]), shard)
	}

	// Randomly select shards to use for decoding.
	seed := uint64(time.Now().UnixNano())
	t.Logf("using random seed: %d", seed)
	rng := rand.New(rand.NewSource(seed))
	indices := rng.Perm(681)

	// Remove all but 342 shards.
	for i := range indices {
		shards[i] = nil
	}

	err = rs.Decode(shards)
	if err != nil {
		require.NoError(t, err)
	}

	// The first 342 restored shards should match the original data.
	require.Equal(t, hex.EncodeToString(bytes.Join(shards[:342], []byte{})), tv.Data)
}

type TestVector struct {
	Data    string `json:"data"`
	Segment struct {
		Segments []struct {
			SegmentEC []string `json:"segment_ec"`
		} `json:"segments"`
	} `json:"segment"`
}
