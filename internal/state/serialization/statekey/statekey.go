package statekey

import (
	"fmt"
	"math"

	"github.com/eigerco/strawberry/pkg/serialization/codec/jam"

	"github.com/eigerco/strawberry/internal/block"
	"github.com/eigerco/strawberry/internal/crypto"
)

const (
	// Chapter component for service account state keys.
	ChapterServiceIndex uint8 = 255
	// Hash component for storage state keys begins this this value little endian encoded.
	HashStorageIndex uint32 = math.MaxUint32
	// Hash component for preimage lookup state keys begins this this value little endian encoded.
	HashPreimageLookupIndex uint32 = math.MaxUint32 - 1
)

// The output of the state key constructor function.
type StateKey [31]byte

// First arity of the stake-key constructor function
// See equation D.1 in the graypaper 0.6.7
func NewBasic(i uint8) StateKey {
	var result StateKey

	// Copy i as the first byte
	result[0] = i

	// The rest of the result is already zero-padded by default
	return result
}

// Second arity of the stake-key constructor function, (uint8, N_S)
// See equation D.1 in the graypaper v0.6.7
func NewService(s block.ServiceId) (StateKey, error) {
	encodedServiceId, err := jam.Marshal(s)
	if err != nil {
		return StateKey{}, err
	}

	var result StateKey

	// Place i as the first byte
	result[0] = ChapterServiceIndex

	// Place encoded service ID bytes at positions 1,3,5,7
	result[1] = encodedServiceId[0]
	result[3] = encodedServiceId[1]
	result[5] = encodedServiceId[2]
	result[7] = encodedServiceId[3]

	return result, nil
}

// Last airity of the stake-key constructor function, (N_S, B)
// See equation D.1 in the graypaper v0.7.0
func NewServiceDict(s block.ServiceId, hashComponent []byte) (StateKey, error) {
	encodedServiceId, err := jam.Marshal(s)
	if err != nil {
		return StateKey{}, err
	}

	hash := crypto.HashData(hashComponent)

	var result StateKey

	// Interleave the first 4 bytes of encodedServiceId with the first 4 bytes of h
	// Interleave bytes from encodedServiceId and h
	result[0] = encodedServiceId[0]
	result[1] = hash[0]
	result[2] = encodedServiceId[1]
	result[3] = hash[1]
	result[4] = encodedServiceId[2]
	result[5] = hash[2]
	result[6] = encodedServiceId[3]
	result[7] = hash[3]

	// Append the rest of h to the result
	copy(result[8:], hash[4:])

	return result, nil
}

// Create a new storage state key.
// ∀(s ↦ a) ∈ δ, (k ↦ v) ∈ as ∶ C(s, E4(2^32 − 1) ⌢ k)
// See equation D.2 in the graypaper v0.6.7
func NewStorage(serviceId block.ServiceId, originalKey []byte) (StateKey, error) {
	hashIndex, err := jam.Marshal(HashStorageIndex)
	if err != nil {
		return StateKey{}, err
	}

	hashComponent := make([]byte, len(hashIndex)+len(originalKey))
	copy(hashComponent[:4], hashIndex)
	copy(hashComponent[4:], originalKey)

	return NewServiceDict(serviceId, hashComponent)
}

// Create a new preimage state key.
// ∀(s ↦ a) ∈ δ, (h ↦ p) ∈ ap ∶ C(s, E4(2^32 −2) ⌢ h)
// See equation D.2 in the graypaper v0.6.7
func NewPreimageLookup(serviceId block.ServiceId, originalHash crypto.Hash) (StateKey, error) {
	hashIndex, err := jam.Marshal(HashPreimageLookupIndex)
	if err != nil {
		return StateKey{}, err
	}

	hashComponent := make([]byte, len(hashIndex)+len(originalHash))
	copy(hashComponent[:4], hashIndex)
	copy(hashComponent[4:], originalHash[:])

	return NewServiceDict(serviceId, hashComponent)
}

// Create a new preimage state key.
// ∀(s ↦ a) ∈ δ, ((h,l) ↦ t) ∈ al ∶ C(s, E4(l) ⌢ h)
// See equation D.2 in the graypaper v0.6.7
func NewPreimageMeta(serviceId block.ServiceId, originalHash crypto.Hash, originalLength uint32) (StateKey, error) {
	encodedLength, err := jam.Marshal(originalLength)
	if err != nil {
		return StateKey{}, err
	}

	hashComponent := make([]byte, len(encodedLength)+len(originalHash))
	copy(hashComponent[:4], encodedLength)
	copy(hashComponent[4:], originalHash[:])

	return NewServiceDict(serviceId, hashComponent)
}

// Checks if the given state key is a chapter key of the format: [i, 0, 0,...]
func (s StateKey) IsChapterKey() bool {
	// Chapter keys should be between 1 and 254
	if !(s[0] > 0 && s[0] < 255) {
		return false
	}

	// And then the rest of the bytes must be 0.
	for _, byte := range s[1:] {
		if byte != 0 {
			return false
		}
	}
	return true
}

// Checks if the given state key is a service account key of the format: [255, n0, 0, n1, 0, n2, 0, n3, 0, 0,...]
// Where n is the service ID (uint32) little endian encoded.
func (s StateKey) IsServiceKey() bool {
	if !(s[0] == ChapterServiceIndex && // Service account keys start with 255.
		s[2] == 0 && s[4] == 0 && s[6] == 0) {
		return false
	}

	// And then the rest of the bytes must be 0.
	for _, byte := range s[8:] {
		if byte != 0 {
			return false
		}
	}

	return true
}

// Checks if the given state key is a preimage lookup key. We can exploit the fact
// that the preimage key is always the hash of it's value.
func (s StateKey) IsPreimageLookupKey(preimageValue []byte) (bool, error) {
	serviceID, _, err := s.ExtractServiceIDHash()
	if err != nil {
		return false, err
	}

	preimageStateKey, err := NewPreimageLookup(serviceID, crypto.HashData(preimageValue))
	if err != nil {
		return false, err
	}

	return preimageStateKey == s, nil
}

// Extracts the chapter and service ID components from a state key of airty 2.
// State key is the format: [i, n0, 0, n1, 0, n2, 0, n3, 0, 0,...]
// where i is an uint8, and n is the service ID (uint32) little endian encoded.
func (s StateKey) ExtractChapterServiceID() (uint8,
	block.ServiceId, error) {
	if !(s[2] == 0 && s[4] == 0 && s[6] == 0) {
		return 0, 0, fmt.Errorf("extracting chapter and service id: not an airty 2 state key")
	}

	// Collect service ID bytes from positions 1,3,5,7 into a slice
	encodedServiceId := []byte{
		s[1],
		s[3],
		s[5],
		s[7],
	}

	var serviceId block.ServiceId
	if err := jam.Unmarshal(encodedServiceId, &serviceId); err != nil {
		return 0, 0, err
	}

	return s[0], serviceId, nil
}

// Extracts the service ID and hash components from a state key of airty 3.
// The state key is the format: [n0, h0, n1, h1, n2, h2, n3, h3, h4, h5,...]
// Where n is the server ID uint32 little endian encoded, and h is the hash component.
func (s StateKey) ExtractServiceIDHash() (block.ServiceId, []byte, error) {
	encodedServiceId := []byte{
		s[0],
		s[2],
		s[4],
		s[6],
	}

	var serviceId block.ServiceId
	if err := jam.Unmarshal(encodedServiceId, &serviceId); err != nil {
		return 0, []byte{}, err
	}

	// 31 byte state key  - 4 bytes for the service ID = 27 bytes for the hash component
	hash := make([]byte, 27)
	hash[0] = s[1]
	hash[1] = s[3]
	hash[2] = s[5]
	copy(hash[3:], s[7:])

	return serviceId, hash, nil
}
