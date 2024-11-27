package state

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"slices"
	"sort"

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

// generateStateKey to generate state key based on i and s
func generateStateKey(i uint8, s block.ServiceId) [32]byte {
	var result [32]byte

	// Place i as the first byte
	result[0] = i

	// Extract individual bytes from s using bit shifting
	result[1] = byte(s >> 24) // n0
	result[3] = byte(s >> 16) // n1
	result[5] = byte(s >> 8)  // n2
	result[7] = byte(s)       // n3

	// result[2,4,6,8] and the rest are already 0 by default
	return result
}

// Function to interleave the first 4 bytes of s and h, then append the rest of h
func generateStateKeyInterleaved(s block.ServiceId, h [32]byte) [32]byte {
	var result [32]byte

	// Convert s into a 4-byte buffer
	sBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(sBuf, uint32(s)) // s is 4 bytes

	// Interleave the first 4 bytes of s with the first 4 bytes of h
	for i := 0; i < 4; i++ {
		// Copy the i-th byte from sBuf
		result[i*2] = sBuf[i]
		// Copy the i-th byte from h
		result[i*2+1] = h[i]
	}

	// Append the rest of h to the result
	copy(result[8:], h[4:])

	return result
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
