package merkle

import (
	"bytes"
	"crypto/ed25519"
	"slices"
	"sort"

	"github.com/eigerco/strawberry/pkg/serialization/codec/jam"

	"github.com/eigerco/strawberry/internal/block"
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/state"
)

// The hash component of the state key constructor function.
// See equation D.1 in the graypaper 0.6.6
type stateConstructorHashComponent [27]byte

// First arity of the stake-key constructor function
// See equation D.1 in the graypaper 0.6.6
func generateStateKeyBasic(i uint8) state.StateKey {
	var result state.StateKey

	// Copy i as the first byte
	result[0] = i

	// The rest of the result is already zero-padded by default
	return result
}

// Second arity of the stake-key constructor function, (uint8, N_S)
// See equation D.1 in the graypaper v0.6.6
func generateStateKeyInterleavedBasic(i uint8, s block.ServiceId) (state.StateKey, error) {
	encodedServiceId, err := jam.Marshal(s)
	if err != nil {
		return state.StateKey{}, err
	}

	var result state.StateKey

	// Place i as the first byte
	result[0] = i

	// Place encoded service ID bytes at positions 1,3,5,7
	result[1] = encodedServiceId[0]
	result[3] = encodedServiceId[1]
	result[5] = encodedServiceId[2]
	result[7] = encodedServiceId[3]

	return result, nil
}

// Last airity of the stake-key constructor function, (N_S, Y_27)
// See equation D.1 in the graypaper v0.6.6
func generateStateKeyInterleaved(s block.ServiceId, h stateConstructorHashComponent) (state.StateKey, error) {
	encodedServiceId, err := jam.Marshal(s)
	if err != nil {
		return state.StateKey{}, err
	}

	var result state.StateKey

	// Interleave the first 4 bytes of encodedServiceId with the first 4 bytes of h
	// Interleave bytes from encodedServiceId and h
	result[0] = encodedServiceId[0]
	result[1] = h[0]
	result[2] = encodedServiceId[1]
	result[3] = h[1]
	result[4] = encodedServiceId[2]
	result[5] = h[2]
	result[6] = encodedServiceId[3]
	result[7] = h[3]

	// Append the rest of h to the result
	copy(result[8:], h[4:])

	return result, nil
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
