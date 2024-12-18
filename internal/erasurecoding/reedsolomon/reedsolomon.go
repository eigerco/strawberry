package reedsolomon

import (
	"C"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"github.com/ebitengine/purego"
)

var (
	reedSolomonEncode func(
		originalShardsCount C.size_t,
		recoveryShardsCount C.size_t,
		shardSize C.size_t,
		originalShards []byte,
		recoveryShardsOut []byte,
	) (cerr int)

	reedSolomonDecode func(
		originalShardsCount C.size_t,
		recoveryShardsCount C.size_t,
		shardSize C.size_t,
		originalShards []byte,
		originalShardsLen C.size_t,
		originalShardsIndexes []C.size_t,
		recoveryShards []byte,
		recoveryShardsLen C.size_t,
		recoveryShardsIndexes []C.size_t,
		shardsRecoveredOut []byte,
		shardsRecoveredIndexesOut []C.size_t,
	) (cerr int)
)

type Encoder struct {
	originalShardsCount int
	recoveryShardsCount int
}

// Create a new reed solomon enocder with the given original shards count and
// recovery shards count.
func New(originalShardsCount, recoveryShardsCount int) *Encoder {
	return &Encoder{
		originalShardsCount: originalShardsCount,
		recoveryShardsCount: recoveryShardsCount,
	}
}

// Takes a slice of data to encode and chunks the data into shards. The
// resulting shards contain the original shards and enough space for the
// recovery shards. Shards can be passed directly to encode. Shards will have a
// length of the original shards count + the recovery shards count. Data is not
// copied, so the input data should not be modified after.
func (r *Encoder) Chunk(data []byte) ([][]byte, error) {
	// Need at least two bytes per chunk.
	if len(data) < r.originalShardsCount*2 {
		return nil, errors.New("data length too short")
	}
	shardSize := (len(data) + r.originalShardsCount - 1) / r.originalShardsCount
	shards := make([][]byte, r.originalShardsCount+r.recoveryShardsCount)

	// Handle all full-sized chunks
	for i := 0; i < r.originalShardsCount-1; i++ {
		start := i * shardSize
		end := start + shardSize
		shards[i] = data[start:end]
	}

	// Handle last chunk with padding
	start := (r.originalShardsCount - 1) * shardSize
	padded := make([]byte, shardSize)
	copy(padded, data[start:])
	shards[r.originalShardsCount-1] = padded

	return shards, nil
}

// Takes shards and fills in the recovery shards. The first original shard count
// indexes should contain the original shards, the remaining recovery shard
// indexes are then filled with recovery shards.
// This can be used to implement C ∶ ⟦Y2⟧342 → ⟦Y2⟧1023 in the graypaper. (Apendix H, v0.5.2-4)
func (r *Encoder) Encode(
	shards [][]byte) error {
	if shardCount(shards[:r.originalShardsCount]) != r.originalShardsCount {
		return errors.New("too few original shards")
	}

	if len(shards) != (r.originalShardsCount + r.recoveryShardsCount) {
		return errors.New("not enough space for recovery shards")
	}

	shardSize := shardSize(shards)

	flatOriginalShards := make([]byte, r.originalShardsCount*shardSize)
	for i, s := range shards[:r.originalShardsCount] {
		copy(flatOriginalShards[i*shardSize:], s)
	}

	recoveryShardsOut := make([]byte, r.recoveryShardsCount*shardSize)

	result := reedSolomonEncode(
		C.size_t(r.originalShardsCount),
		C.size_t(r.recoveryShardsCount),
		C.size_t(shardSize),
		flatOriginalShards,
		recoveryShardsOut)
	if result != 0 {
		return errors.New("unable to encode data")
	}

	for i := 0; i < r.recoveryShardsCount; i++ {
		start := i * shardSize
		end := start + shardSize
		shards[i+r.originalShardsCount] = recoveryShardsOut[start:end]
	}
	return nil
}

// Takes a slice of shards which should have at least original shard count
// shards and fills in the missing original shards. Missing shards are with nil
// or a length of zero before decoding.
// This can be used to implement R ∶ ℘⟨⎧⎩Y2, N1023⎫⎭⟩342 → ⟦Y2⟧342 in the graypaper. (Apendix H, v0.5.2-4)
func (r *Encoder) Decode(shards [][]byte) error {
	if shardCount(shards) < r.originalShardsCount {
		return errors.New("too few shards")
	}
	shardSize := shardSize(shards)
	if shardSize == 0 {
		// todo better error name
		return errors.New("invalid shard size")
	}

	flatOriginalShards := []byte{}
	flatOriginalShardsIndexes := []C.size_t{}
	for i, s := range shards[:r.originalShardsCount] {
		if len(s) != 0 {
			flatOriginalShards = append(flatOriginalShards, s...)
			flatOriginalShardsIndexes = append(flatOriginalShardsIndexes, C.size_t(i))
		}
	}

	flatRecoveryShards := []byte{}
	flatRecoveryShardsIndexes := []C.size_t{}
	for i, s := range shards[r.originalShardsCount:] {
		if len(s) != 0 {
			flatRecoveryShards = append(flatRecoveryShards, s...)
			flatRecoveryShardsIndexes = append(flatRecoveryShardsIndexes, C.size_t(i))
		}
	}

	shardCountOriginal := shardCount(shards[:r.originalShardsCount])
	// Shards we already have aren't restored.
	restoredShardsCount := r.originalShardsCount - shardCountOriginal
	restoredShards := make([]byte, restoredShardsCount*shardSize)
	restoredShardsIndexes := make([]C.size_t, restoredShardsCount)

	result := reedSolomonDecode(
		C.size_t(r.originalShardsCount),
		C.size_t(r.recoveryShardsCount),
		C.size_t(shardSize),
		flatOriginalShards,
		C.size_t(len(flatOriginalShards)),
		flatOriginalShardsIndexes,
		flatRecoveryShards,
		C.size_t(len(flatRecoveryShards)),
		flatRecoveryShardsIndexes,
		restoredShards,
		restoredShardsIndexes)
	if result != 0 {
		return errors.New("unable to decode data")
	}

	for i := 0; i < restoredShardsCount; i++ {
		start := i * shardSize
		end := start + shardSize
		index := int(restoredShardsIndexes[i])
		shards[index] = restoredShards[start:end]
	}

	return nil
}

// Returns the first non nil or length zero shard length.
func shardSize(shards [][]byte) int {
	for _, shard := range shards {
		if len(shard) != 0 {
			return len(shard)
		}
	}
	return 0
}

// Returns the count of non nil or length zero shards.
func shardCount(shards [][]byte) int {
	count := 0
	for _, shard := range shards {
		if len(shard) != 0 {
			count++
		}
	}
	return count
}

func init() {
	// Load the Rust shared library in the init function
	libPath, err := getErasurecodingLibaryPath()
	if err != nil {
		fmt.Println("Failed to load erasure coding library path:", err)
		os.Exit(1)
	}

	// Load the Rust shared library
	lib, err := purego.Dlopen(libPath, purego.RTLD_NOW|purego.RTLD_GLOBAL)
	if err != nil {
		fmt.Println("Failed to load erasure coding library:", err)
		os.Exit(1)
	}

	// Register the Rust FFI functions with Go using purego
	purego.RegisterLibFunc(&reedSolomonEncode, lib, "reed_solomon_encode")
	purego.RegisterLibFunc(&reedSolomonDecode, lib, "reed_solomon_decode")
}

func getErasurecodingLibaryPath() (string, error) {
	var ext string
	switch runtime.GOOS {
	case "darwin":
		ext = "dylib"
	case "linux":
		ext = "so"
	default:
		return "", fmt.Errorf("GOOS=%s is not supported", runtime.GOOS)
	}

	_, filePath, _, ok := runtime.Caller(0)
	if !ok {
		return "", fmt.Errorf("unable to retrieve the caller info")
	}

	baseDir := filepath.Dir(filePath)
	libPath := filepath.Join(baseDir, fmt.Sprintf("../../../erasurecoding/target/release/liberasurecoding.%s", ext))

	return libPath, nil
}
