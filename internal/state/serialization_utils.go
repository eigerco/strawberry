package state

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"github.com/eigerco/strawberry/internal/block"
	"github.com/eigerco/strawberry/internal/crypto"
	"slices"
	"sort"
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

	// Convert s into a 4-byte buffer and place it starting at result[1]
	sBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(sBuf, uint32(s)) // s is 4 bytes in BigEndian format

	// Copy the 4-byte sBuf to result starting at index 1
	copy(result[1:], sBuf)

	// The rest of result is already zero-padded by default
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
func calculateFootprintSize(storage map[crypto.Hash][]byte, preimageMeta map[PreImageMetaKey]PreimageHistoricalTimeslots) uint64 {
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

// bitwiseNotExceptFirst4Bytes to apply bitwise NOT to all bytes except the first 4
func bitwiseNotExceptFirst4Bytes(h crypto.Hash) [28]byte {
	// Clone the original array into a new one
	var result [28]byte
	copy(result[:], h[:])

	// Apply bitwise NOT to all bytes except the first 4
	for i := 4; i < len(result); i++ {
		result[i] = ^result[i]
	}

	return result
}
