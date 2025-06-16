package serialization

import (
	"fmt"

	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/service"
	"github.com/eigerco/strawberry/internal/state"
	"github.com/eigerco/strawberry/internal/state/serialization/statekey"
	"github.com/eigerco/strawberry/pkg/serialization/codec/jam"
)

// DeserializeState deserializes the given map of state keys to byte slices into a State object.
func DeserializeState(serializedState map[statekey.StateKey][]byte) (state.State, error) {
	deserializedState := state.State{}

	// Helper function to deserialize individual fields for chapter state keys.
	deserializeField := func(key uint8, target interface{}) error {
		stateKey := statekey.NewBasic(key)
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
		{3, &deserializedState.RecentHistory},
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
	var serviceKeys, storageKeys, preimageLookupKeys []statekey.StateKey
	for sk := range serializedState {
		isStorageKey, err := sk.IsStorageKey()
		if err != nil {
			return deserializedState, fmt.Errorf("error checking if key is storage key: %w", err)
		}
		isPreimageLookupKey, err := sk.IsPreimageLookupKey()
		if err != nil {
			return deserializedState, fmt.Errorf("error checking if key is preimage lookup key: %w", err)
		}

		if sk.IsChapterKey() {
			continue
		} else if sk.IsServiceKey() {
			serviceKeys = append(serviceKeys, sk)
		} else if isStorageKey {
			storageKeys = append(storageKeys, sk)
		} else if isPreimageLookupKey {
			preimageLookupKeys = append(preimageLookupKeys, sk)
		}
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

	/// Deserialize Storage
	for _, storageKey := range storageKeys {
		if err := deserializeStorage(&deserializedState, storageKey, serializedState[storageKey]); err != nil {
			return deserializedState, err
		}
	}

	// Deserialize Preimage Meta
	err := deserializePreimageMeta(&deserializedState, serializedState)
	if err != nil {
		return deserializedState, err
	}

	return deserializedState, nil
}

// DeserializeService deserializes a service account from the given state key and encoded value.
func deserializeService(state *state.State, sk statekey.StateKey, encodedValue []byte) error {
	if !sk.IsServiceKey() {
		return fmt.Errorf("deserialize service: expected service account key, got %x", sk[:])
	}

	if state.Services == nil {
		state.Services = make(service.ServiceState)
	}

	_, serviceId, err := sk.ExtractChapterServiceID()
	if err != nil {
		return fmt.Errorf("deserialize service: error extracting service ID: %w", err)
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

	serviceAccount := service.ServiceAccount{
		CodeHash:               combined.CodeHash,
		Balance:                combined.Balance,
		GasLimitForAccumulator: combined.GasLimitForAccumulator,
		GasLimitOnTransfer:     combined.GasLimitOnTransfer,
	}

	state.Services[serviceId] = serviceAccount

	return nil
}

// deserializeStorage deserializes a storage account from the given state key and encoded value.
func deserializeStorage(state *state.State, sk statekey.StateKey, encodedValue []byte) error {
	ok, err := sk.IsStorageKey()
	if err != nil {
		return fmt.Errorf("deserialize storage: error checking if key is storage key: %w", err)
	}
	if !ok {
		return fmt.Errorf("deserialize storage: expected storage key, got '%x'", sk[:])
	}

	serviceId, _, err := sk.ExtractServiceIDHash()
	if err != nil {
		return fmt.Errorf("deserialize storage: error extracting service ID: %w", err)
	}

	if state.Services == nil {
		return fmt.Errorf("deserializing storage: services map empty")
	}

	serviceAccount, ok := state.Services[serviceId]
	if !ok {
		return fmt.Errorf("deserializing storage: service ID '%v' does not exist", serviceId)
	}

	serviceAccount.Storage = service.NewAccountStorage()

	serviceAccount.Storage.Set(sk, uint32(len(sk)), encodedValue)

	state.Services[serviceId] = serviceAccount

	return nil
}

// deserializePreimageLookup deserializes a preimage lookup from the given state key and encoded value.
// The original preimage lookup hash is found by simply hashing the decoded value.
func deserializePreimageLookup(state *state.State, sk statekey.StateKey, encodedValue []byte) error {
	ok, err := sk.IsPreimageLookupKey()
	if err != nil {
		return fmt.Errorf("deserialize preimage lookup: error checking if key is preimage lookup key: %w", err)
	}
	if !ok {
		return fmt.Errorf("deserialize preimage lookup: expected preimage lookup key, got '%x'", sk[:])
	}

	serviceId, _, err := sk.ExtractServiceIDHash()
	if err != nil {
		return fmt.Errorf("deserialize preimage lookup: error extracting service ID: %w", err)
	}

	if state.Services == nil {
		return fmt.Errorf("deserializing preimage lookup: services map empty")
	}

	serviceAccount, ok := state.Services[serviceId]
	if !ok {
		return fmt.Errorf("deserializing preimage lookup: service ID '%v' does not exist", serviceId)
	}

	if serviceAccount.PreimageLookup == nil {
		serviceAccount.PreimageLookup = map[crypto.Hash][]byte{}
	}

	key := crypto.HashData(encodedValue)
	// Check that the incoming state key matches one constructed from this key.
	// I.e we are checking that the incoming partial hash in the state key
	// h1..24 matches ours. If not then the state key is invalid even though it
	// might have had a valid blob.
	newSk, err := statekey.NewPreimageLookup(serviceId, key)
	if err != nil {
		return fmt.Errorf("deserializing preimage lookup: error creating preimage lookup key: %w", err)
	}
	if sk != newSk {
		return fmt.Errorf("deserializing preimage lookup: preimage hash does not match original hash")
	}

	serviceAccount.PreimageLookup[key] = encodedValue

	state.Services[serviceId] = serviceAccount

	return nil
}

// desserializePreimageMeta deserializes the preimage meta from the given serialized state.
// PreimageMeta is a special case. We know that for each preimage in a service,
// there should be a corresponding preimage meta entry (See equation 9.6 of the
// GP v0.6.6). Knowing that we loop through each preimage and create a preimage
// meta state key for it using it's length and hash. We can then look that key
// up in the serialized state, and fetch it's value, and use that to rebuild the
// preimage meta entry.
func deserializePreimageMeta(state *state.State, serializedState map[statekey.StateKey][]byte) error {
	if state.Services == nil {
		return fmt.Errorf("deserialize preimage meta: services map empty")
	}

	for serviceId, serviceAccount := range state.Services {
		if serviceAccount.PreimageLookup == nil {
			return fmt.Errorf("deserializing preimage meta: service account '%v' empty preimage meta map", serviceId)
		}

		for preimageHash, preimageBlob := range serviceAccount.PreimageLookup {
			preimageLength := uint32(len(preimageBlob))
			sk, err := statekey.NewPreimageMeta(serviceId, preimageHash, preimageLength)
			if err != nil {
				return fmt.Errorf("deserialize preimage meta: error creating preimage meta state key: %w", err)
			}

			encodedValue, ok := serializedState[sk]
			if !ok {
				return fmt.Errorf("deserialize preimage meta: missing preimage meta state key %v", sk)
			}

			key := service.PreImageMetaKey{
				Hash:   preimageHash,
				Length: service.PreimageLength(preimageLength),
			}

			historicalPreimageMeta := service.PreimageHistoricalTimeslots{}
			if err := jam.Unmarshal(encodedValue, &historicalPreimageMeta); err != nil {
				return fmt.Errorf("deserialize preimage meta: error unmarshalling historical timeslots: %w", err)
			}

			if serviceAccount.PreimageMeta == nil {
				serviceAccount.PreimageMeta = make(map[service.PreImageMetaKey]service.PreimageHistoricalTimeslots)
			}

			serviceAccount.PreimageMeta[key] = historicalPreimageMeta
		}

		state.Services[serviceId] = serviceAccount
	}

	return nil
}
