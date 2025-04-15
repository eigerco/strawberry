package erasurecoding

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"testing"
	"time"

	"github.com/eigerco/strawberry/internal/common"
	"github.com/eigerco/strawberry/internal/testutils"
	"github.com/stretchr/testify/require"
)

func TestUnzipLace(t *testing.T) {
	testCases := []struct {
		name string
		data []byte
		n    int
		want []byte
	}{
		{
			name: "perfectlyDivsible",
			data: []byte{1, 2, 3, 4, 5, 6},
			n:    2,
			want: []byte{1, 2, 3, 4, 5, 6},
		},
		{
			name: "withPadding",
			data: []byte{1, 2, 3, 4, 5},
			n:    2,
			want: []byte{1, 2, 3, 4, 5},
		},
		{
			name: "singles",
			data: []byte{1, 2, 3},
			n:    3,
			want: []byte{1, 2, 3},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			chunks := unzip(tc.n, tc.data)
			data := lace(chunks, len(tc.data))

			require.Equal(t, data, tc.want)
		})
	}
}

func TestEncodeDecodeRoundTripRandom(t *testing.T) {
	dataSizes := []int{
		1,
		684,
		1368,
		2052,
		4096,
		4104,
	}

	seed := time.Now().UnixNano()
	t.Logf("using random seed: %d", seed)
	rng := rand.New(rand.NewSource(seed))

	for _, size := range dataSizes {
		t.Run(fmt.Sprintf("size%d", size), func(t *testing.T) {
			// Generate some random data.
			data := make([]byte, size)
			_, err := rng.Read(data)
			require.NoError(t, err)

			// Encode the data
			shards, err := Encode(data)
			require.NoError(t, err)
			require.Equal(t, len(shards), OriginalShards+RecoveryShards)

			// Randomly remove RecoveryShards shards.
			indices := rng.Perm(RecoveryShards)
			for i := range indices {
				shards[i] = nil
			}

			// Decode the data with the remaining shards.
			dataOut, err := Decode(shards, size)
			if err != nil {
				t.Fatalf("Decode failed: %v", err)
			}

			require.Equal(t, data, dataOut)
		})
	}
}

func TestEncodeDecodeInitialTestVector(t *testing.T) {
	jsonData, err := os.ReadFile("reedsolomon/test_data.json")
	require.NoError(t, err)

	tv := TestVector{}
	err = json.Unmarshal(jsonData, &tv)
	require.NoError(t, err)
	data := testutils.MustFromHex(t, tv.Data)

	result, err := Encode(data)
	require.NoError(t, err)

	decodedData, err := Decode(result, len(data))
	require.NoError(t, err)

	require.Equal(t, decodedData, data)
}
func TestEncodeFailureCases(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
	}{
		{
			name:  "emptyData",
			input: []byte{},
		},
		{
			name:  "dataTooLarge",
			input: make([]byte, common.MaxWorkPackageSize+1),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Encode(tt.input)
			require.Error(t, err)
		})
	}
}

func TestDecodeFailureCases(t *testing.T) {
	tests := []struct {
		name    string
		shards  [][]byte
		outSize int
	}{
		{
			name:   "tooFewShards",
			shards: testShards(OriginalShards-1, ChunkShardSize),
		},
		{
			name:   "invalidShardSize",
			shards: testShards(OriginalShards+RecoveryShards, ChunkShardSize+1),
		},
		{
			name:   "nilShards",
			shards: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Decode(tt.shards, 100)
			require.Error(t, err)
		})
	}
}

// Helper function to create test shards with specific size.
func testShards(count, size int) [][]byte {
	shards := make([][]byte, count)
	for i := range shards {
		shards[i] = make([]byte, size)
	}
	return shards
}

type TestVector struct {
	Data    string `json:"data"`
	Segment struct {
		Segments []struct {
			SegmentEC []string `json:"segment_ec"`
		} `json:"segments"`
	} `json:"segment"`
}
