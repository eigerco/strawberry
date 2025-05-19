package merkle

import (
	"encoding/hex"
	"fmt"

	"github.com/eigerco/strawberry/internal/block"
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/service"
	"github.com/eigerco/strawberry/internal/state"
	"github.com/eigerco/strawberry/pkg/serialization/codec/jam"
)

// DeserializeState deserializes the given map of state keys to byte slices into a State object.
func DeserializeState(serializedState map[state.StateKey][]byte) (state.State, error) {
	deserializedState := state.State{}

	// Helper function to deserialize individual fields for chapter state keys.
	deserializeField := func(key uint8, target interface{}) error {
		stateKey := generateStateKeyBasic(key)
		encodedValue, ok := serializedState[stateKey]
		if !ok {
			return fmt.Errorf("deserialize state: missing state key %v", key)
		}
		return jam.Unmarshal(encodedValue, target)
	}

	// Deserialize basic fields (chapter state keys)
	// These can simply be looked up.
	basicFields := []struct {
		key   uint8
		value any
	}{
		{1, &deserializedState.CoreAuthorizersPool},
		{2, &deserializedState.PendingAuthorizersQueues},
		{3, &deserializedState.RecentBlocks},
		{4, &deserializedState.ValidatorState.SafroleState},
		{5, &deserializedState.PastJudgements},
		{6, &deserializedState.EntropyPool},
		{7, &deserializedState.ValidatorState.QueuedValidators},
		{8, &deserializedState.ValidatorState.CurrentValidators},
		{9, &deserializedState.ValidatorState.ArchivedValidators},
		{10, &deserializedState.CoreAssignments},
		{11, &deserializedState.TimeslotIndex},
		{12, &deserializedState.PrivilegedServices},
		{13, &deserializedState.ActivityStatistics},
		{14, &deserializedState.AccumulationQueue},
		{15, &deserializedState.AccumulationHistory},
	}

	for _, field := range basicFields {
		if err := deserializeField(field.key, field.value); err != nil {
			return deserializedState, fmt.Errorf("error deserializing basic field with key %v, value, %+v: %w", field.key, field.value, err)
		}
	}

	// Sort keys into service account keys and preimage lookup keys.
	var serviceKeys, preimageLookupKeys []state.StateKey
	for stateKey := range serializedState {
		if IsChapterKey(stateKey) {
			continue
		} else if IsServiceAccountKey(stateKey) {
			serviceKeys = append(serviceKeys, stateKey)
		} else if IsPreimageLookupKey(stateKey) {
			preimageLookupKeys = append(preimageLookupKeys, stateKey)
		}

		// TODO storage and preimage meta keys.
	}

	// Deserialize Services
	for _, serviceKey := range serviceKeys {
		if err := deserializeService(&deserializedState, serviceKey, serializedState[serviceKey]); err != nil {
			return deserializedState, err
		}
	}

	// Deserialize Preimage Lookups
	for _, preimageLookupKey := range preimageLookupKeys {
		if err := deserializePreimageLookup(&deserializedState, preimageLookupKey, serializedState[preimageLookupKey]); err != nil {
			return deserializedState, err
		}
	}

	return deserializedState, nil
}

// DeserializeService deserializes a service account from the given state key and encoded value.
func deserializeService(state *state.State, stateKey state.StateKey, encodedValue []byte) error {
	if !IsServiceAccountKey(stateKey) {
		return fmt.Errorf("deserialize service: expected service account key, got %x", stateKey[:])
	}

	if state.Services == nil {
		state.Services = make(service.ServiceState)
	}

	_, serviceId, err := extractStateKeyChapterServiceID(stateKey)
	if err != nil {
		return err
	}

	// Deserialize the combined fields (CodeHash, Balance, etc.)
	var combined struct {
		CodeHash               crypto.Hash
		Balance                uint64
		GasLimitForAccumulator uint64
		GasLimitOnTransfer     uint64
		FootprintSize          uint64
		FootprintItems         uint32
	}
	if err := jam.Unmarshal(encodedValue, &combined); err != nil {
		return fmt.Errorf("deserialize service: error unmarshalling: %w", err)
	}

	// Create and populate the ServiceAccount from the deserialized data
	serviceAccount := service.ServiceAccount{
		CodeHash:               combined.CodeHash,
		Balance:                combined.Balance,
		GasLimitForAccumulator: combined.GasLimitForAccumulator,
		GasLimitOnTransfer:     combined.GasLimitOnTransfer,
	}

	state.Services[serviceId] = serviceAccount

	return nil
}

// DeserializePreimageLookup deserializes a preimage lookup from the given state key and encoded value.
// The original preimage lookup hash is found by simply hashing the decoded value.
func deserializePreimageLookup(state *state.State, stateKey state.StateKey, encodedValue []byte) error {
	if !IsPreimageLookupKey(stateKey) {
		return fmt.Errorf("deserialize preimage lookup: expected preimage lookup key, got '%v'", hex.EncodeToString(stateKey[:]))
	}

	serviceId, _, err := extractStateKeyServiceIDHash(stateKey)
	if err != nil {
		return err
	}

	if state.Services == nil {
		return fmt.Errorf("deserializing preimage lookup: services map empty")
	}

	serviceAccount, ok := state.Services[serviceId]
	if !ok {
		return fmt.Errorf("deserializing preimage lookup: service ID '%v' does not exist", serviceId)
	}

	preimageBlob := []byte{}
	if err := jam.Unmarshal(encodedValue, &preimageBlob); err != nil {
		return fmt.Errorf("deserializing preimage lookup: error unmarshalling: %w", err)
	}

	if serviceAccount.PreimageLookup == nil {
		serviceAccount.PreimageLookup = map[crypto.Hash][]byte{}
	}

	key := crypto.HashData(preimageBlob)
	serviceAccount.PreimageLookup[key] = preimageBlob

	state.Services[serviceId] = serviceAccount

	return nil
}

// Checks if the given state key is a chapter key of the format: [i, 0, 0,...]
func IsChapterKey(stateKey state.StateKey) bool {
	// Chapter keys start with 1-15.
	if !(stateKey[0] > 0 && stateKey[0] < 16) {
		return false
	}

	// And then the rest of the bytes must be 0.
	for _, byte := range stateKey[1:] {
		if byte != 0 {
			return false
		}
	}
	return true
}

// Checks if the given state key is a service account key of the format: [255, n0, 0, n1, 0, n2, 0, n3, 0, 0,...]
// Where n is the server ID uint32 little endian encoded.
func IsServiceAccountKey(stateKey state.StateKey) bool {
	if !(stateKey[0] == ChapterServiceIndex && // Service account keys start with 255.
		stateKey[2] == 0 && stateKey[4] == 0 && stateKey[6] == 0) {
		return false
	}

	// And then the rest of the bytes must be 0.
	for _, byte := range stateKey[8:] {
		if byte != 0 {
			return false
		}
	}

	return true
}

// Checks if the given state key is a preimage lookup key of the format: [n0, 0xFE, n1, 0xFF, n2, 0xFF, n3, 0xFF, h4, h5,...]
// Where n is the server ID uint32 little endian encoded, and h is the hash component.
func IsPreimageLookupKey(stateKey state.StateKey) bool {
	// The preimage lookup keys hash component starts with max(uint32) - 1,
	// little endian encoded, which is 0xFEFFFFFF. This is interleaved with the
	// service ID.
	return stateKey[1] == 0xFE &&
		stateKey[3] == 0xFF &&
		stateKey[5] == 0xFF &&
		stateKey[7] == 0xFF

}

// Extracts the chapter and service ID components from a state key of airty 2.
// State key is the format: [i, n0, 0, n1, 0, n2, 0, n3, 0, 0,...]
// where i is an uint8, and n is the server ID uint32 little endian encoded.
func extractStateKeyChapterServiceID(stateKey state.StateKey) (uint8,
	block.ServiceId, error) {
	if !(stateKey[2] == 0 && stateKey[4] == 0 && stateKey[6] == 0) {
		return 0, 0, fmt.Errorf("extracting chapter and service id: not an airty 2 state key")
	}

	// Collect service ID bytes from positions 1,3,5,7 into a slice
	encodedServiceId := []byte{
		stateKey[1],
		stateKey[3],
		stateKey[5],
		stateKey[7],
	}

	var serviceId block.ServiceId
	if err := jam.Unmarshal(encodedServiceId, &serviceId); err != nil {
		return 0, 0, err
	}

	return stateKey[0], serviceId, nil
}

// Extracts the service ID and hash components from a state key of airty 3.
// The state key is the format: [n0, h0, n1, h1, n2, h2, n3, h3, h4, h5,...]
// Where n is the server ID uint32 little endian encoded, and h is the hash component.
func extractStateKeyServiceIDHash(stateKey state.StateKey) (block.ServiceId, stateConstructorHashComponent, error) {
	encodedServiceId := []byte{
		stateKey[0],
		stateKey[2],
		stateKey[4],
		stateKey[6],
	}

	var serviceId block.ServiceId
	if err := jam.Unmarshal(encodedServiceId, &serviceId); err != nil {
		return 0, stateConstructorHashComponent{}, err
	}

	hash := stateConstructorHashComponent{}
	hash[0] = stateKey[1]
	hash[1] = stateKey[3]
	hash[2] = stateKey[5]
	copy(hash[3:], stateKey[7:])

	return serviceId, hash, nil
}
