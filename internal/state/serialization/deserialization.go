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
	var serviceKeys, storageKeys, preimageLookupKeys []statekey.StateKey
	for sk := range serializedState {
		if sk.IsChapterKey() {
			continue
		} else if sk.IsServiceKey() {
			serviceKeys = append(serviceKeys, sk)
		} else if sk.IsStorageKey() {
			storageKeys = append(storageKeys, sk)
		} else if sk.IsPreimageLookupKey() {
			preimageLookupKeys = append(preimageLookupKeys, sk)
		}

		// TODO preimage meta keys.
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

// deserializeStorage deserializes a storage account from the given state key and encoded value.
func deserializeStorage(state *state.State, sk statekey.StateKey, encodedValue []byte) error {
	if !sk.IsStorageKey() {
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

	if serviceAccount.Storage == nil {
		serviceAccount.Storage = map[statekey.StateKey][]byte{}
	}

	serviceAccount.Storage[sk] = encodedValue

	state.Services[serviceId] = serviceAccount

	return nil
}

// deserializePreimageLookup deserializes a preimage lookup from the given state key and encoded value.
// The original preimage lookup hash is found by simply hashing the decoded value.
func deserializePreimageLookup(state *state.State, sk statekey.StateKey, encodedValue []byte) error {
	if !sk.IsPreimageLookupKey() {
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
	serviceAccount.PreimageLookup[key] = encodedValue

	state.Services[serviceId] = serviceAccount

	return nil
}
