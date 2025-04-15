package erasurecoding

import (
	"bytes"
	"errors"

	"github.com/eigerco/strawberry/internal/common"
	"github.com/eigerco/strawberry/internal/erasurecoding/reedsolomon"
)

// These parameters allow data to be retrieved even when only 1/3 of the
// validators are available.
const (
	OriginalShards = common.ErasureCodingOriginalShards             // Number of original data shards.
	RecoveryShards = common.NumberOfValidators - OriginalShards     // Number of recovery data shards.
	ChunkShardSize = common.ErasureCodingChunkSize / OriginalShards // In bytes.
)

// Encode transforms input data into striped erasure-coded shards using
// Reed-Solomon encoding. It splits the data into chunks of ChunkSize bytes,
// then generates OriginalShards + RecoveryShards total shards. If data cannot
// be evenly split it will be padded with zeros. The resulting shards can
// tolerate the loss of up to RecoveryShards number of shards while still being
// able to reconstruct the original data.
// Implements equation H.6 from the graypaper (v0.5.3).
func Encode(data []byte) ([][]byte, error) {
	if len(data) == 0 {
		return nil, errors.New("data has length 0")
	}
	if len(data) > common.MaxWorkPackageSize {
		return nil, errors.New("data length too long")
	}

	encoder, err := reedsolomon.New(OriginalShards, RecoveryShards)
	if err != nil {
		return nil, errors.New("error creating encoder")
	}

	chunks := unzip(common.ErasureCodingChunkSize, data)
	if len(chunks) == 0 {
		return nil, errors.New("couldn't unzip data")
	}

	finalShards := make([][]byte, OriginalShards+RecoveryShards)
	for i := range finalShards {
		finalShards[i] = make([]byte, len(chunks)*ChunkShardSize)
	}
	for i, c := range chunks {
		shards, err := encoder.Chunk(c)
		if err != nil {
			return nil, err
		}
		err = encoder.Encode(shards)
		if err != nil {
			return nil, err
		}

		// Transpose and copy to result in one go.
		for j := range finalShards {
			start := i * ChunkShardSize
			copy(finalShards[j][start:start+ChunkShardSize], shards[j])
		}
	}

	return finalShards, nil
}

// Decode reconstructs the original data from striped erasure-coded shards using
// Reed-Solomon decoding. It requires at least OriginalShards number of shards
// to successfully recover the data. Missing or corrupted shards can be passed
// as nil or empty byte slices. The outSize parameter specifies the expected
// length of the original data.
// Implements equation H.7 from the graypaper (v0.5.3).
func Decode(shards [][]byte, outSize int) ([]byte, error) {
	if reedsolomon.ShardCount(shards) < OriginalShards {
		return nil, errors.New("too few shards")
	}

	shardSize := reedsolomon.ShardSize(shards)
	if shardSize%ChunkShardSize != 0 {
		return nil, errors.New("invalid shard size")
	}

	if outSize > shardSize*OriginalShards {
		return nil, errors.New("out size too long")
	}

	encoder, err := reedsolomon.New(OriginalShards, RecoveryShards)
	if err != nil {
		return nil, errors.New("error creating encoder")
	}

	noChunks := shardSize / ChunkShardSize
	chunkShards := make([][][]byte, noChunks)
	for i := 0; i < len(chunkShards); i++ {
		chunkShards[i] = make([][]byte, len(shards))
	}

	for i, s := range shards {
		if len(s) == 0 {
			continue
		}
		for j := range chunkShards {
			start := j * ChunkShardSize
			chunkShards[j][i] = s[start : start+ChunkShardSize]
		}
	}

	unzippedChunks := make([][]byte, noChunks)
	for i, c := range chunkShards {
		err := encoder.Decode(c)
		if err != nil {
			return nil, err
		}
		unzippedChunks[i] = bytes.Join(c[0:OriginalShards], []byte(""))
	}

	return lace(unzippedChunks, outSize), nil
}

// unzip stripes data into n-sized chunks by distributing bytes column-wise.
// For input data [1,2,3,4,5,6] and n=2, it produces chunks: [[1,3,5], [2,4,6]]
// If the input data length is not perfectly divisible by n, the final chunk
// will be padded with zeros. For example, data [1,2,3,4,5] and n=2 produces:
// [[1,3,5], [2,4,0]] This transformation prepares data for erasure coding by
// ensuring even distribution across shards. Returns nil if n <= 0.
// Implements equation H.4 from the graypaper (v0.5.3).
func unzip(n int, data []byte) [][]byte {
	if n <= 0 {
		return nil
	}

	k := (len(data) + n - 1) / n

	result := make([][]byte, k)

	for i := range result {
		result[i] = make([]byte, n)
	}

	for i, b := range data {
		result[i%k][i/k] = b
	}

	return result
}

// lace combines multiple chunks back into a single byte slice by reading
// column-wise. It performs the inverse operation of unzip. For input chunks
// [[1,3,5], [2,4,6]] and outSize=6, it produces: [1,2,3,4,5,6]. The outSize
// parameter determines the length of the final output slice which should match
// the length of the original data (this removes any padding that was added by
// zip).
// Implements equation H.5 from the graypaper (v0.5.3).
func lace(chunks [][]byte, outSize int) []byte {
	if len(chunks) == 0 {
		return nil
	}

	k := len(chunks)
	result := make([]byte, outSize)
	for i := range result {
		result[i] = chunks[i%k][i/k]
	}

	return result
}
