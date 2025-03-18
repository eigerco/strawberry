package merkle

import (
	"bytes"
	"crypto/ed25519"
	"slices"
	"sort"

	"github.com/eigerco/strawberry/pkg/serialization/codec/jam"

	"github.com/eigerco/strawberry/internal/block"
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/service"
)

// generateStateKeyBasic to generate state key based only on i
func generateStateKeyBasic(i uint8) [32]byte {
	var result [32]byte

	// Copy i as the first byte
	result[0] = i

	// The rest of the result is already zero-padded by default
	return result
}

// generateStateKeyInterleavedBasic to generate state key based on i and s
func generateStateKeyInterleavedBasic(i uint8, s block.ServiceId) ([32]byte, error) {
	encodedServiceId, err := jam.Marshal(s)
	if err != nil {
		return [32]byte{}, err
	}

	var result [32]byte

	// Place i as the first byte
	result[0] = i

	// Place encoded service ID bytes at positions 1,3,5,7
	for j := 0; j < 4; j++ {
		result[1+j*2] = encodedServiceId[j]
	}

	return result, nil
}

// Function to interleave the first 4 bytes of s and h, then append the rest of h
func generateStateKeyInterleaved(s block.ServiceId, h [32]byte) ([32]byte, error) {
	encodedServiceId, err := jam.Marshal(s)
	if err != nil {
		return [32]byte{}, err
	}

	var result [32]byte

	// Interleave the first 4 bytes of encodedServiceId with the first 4 bytes of h
	for i := 0; i < 4; i++ {
		result[i*2] = encodedServiceId[i]
		result[i*2+1] = h[i]
	}

	// Append the rest of h to the result
	copy(result[8:], h[4:])

	return result, nil
}

// calculateFootprintSize calculates the storage footprint size (al) based on Equation 94.
func calculateFootprintSize(storage map[crypto.Hash][]byte, preimageMeta map[service.PreImageMetaKey]service.PreimageHistoricalTimeslots) uint64 {
	var totalSize uint64 = 0

	// Calculate the footprint size for the preimage metadata
	for key := range preimageMeta {
		totalSize += uint64(81 + key.Length)
	}

	// Calculate the footprint size for the storage items
	for _, value := range storage {
		totalSize += uint64(32 + len(value))
	}

	return totalSize
}

// combineEncoded takes multiple encoded byte arrays and concatenates them into a single byte array.
func combineEncoded(components ...[]byte) []byte {
	var buffer bytes.Buffer

	for _, component := range components {
		buffer.Write(component)
	}

	return buffer.Bytes()
}

// sortByteSlicesCopy returns a sorted copy of a slice of some byte-based types
func sortByteSlicesCopy(slice interface{}) interface{} {
	switch v := slice.(type) {
	case []crypto.Hash:
		// Clone the slice to avoid modifying the original
		copySlice := slices.Clone(v)
		sort.Slice(copySlice, func(i, j int) bool {
			return bytes.Compare(copySlice[i][:], copySlice[j][:]) < 0
		})
		return copySlice
	case []ed25519.PublicKey:
		// Clone the slice to avoid modifying the original
		copySlice := slices.Clone(v)
		sort.Slice(copySlice, func(i, j int) bool {
			return bytes.Compare(copySlice[i], copySlice[j]) < 0
		})
		return copySlice
	default:
		panic("unsupported type for sorting")
	}
}
