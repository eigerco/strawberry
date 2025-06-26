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
		{16, &deserializedState.AccumulationOutputLog},
	}

	for _, field := range basicFields {
		if err := deserializeField(field.key, field.value); err != nil {
			return deserializedState, fmt.Errorf("error deserializing basic field with key %v, value, %+v: %w", field.key, field.value, err)
		}
	}

	// Find service keys
	var serviceKeys, preimageLookupKeys, storageOrPreimageMetaKeys []statekey.StateKey
	for sk, value := range serializedState {
		if sk.IsChapterKey() {
			continue
		}

		if sk.IsServiceKey() {
			serviceKeys = append(serviceKeys, sk)
			continue
		}

		ok, err := sk.IsPreimageLookupKey(value)
		if err != nil {
			return deserializedState, fmt.Errorf("error checking if key is preimage lookup key: %w", err)
		}
		if ok {
			preimageLookupKeys = append(preimageLookupKeys, sk)
			continue
		}

		// Any remaining keys must be storage or preimage meta keys, and we have
		// no way to distinguish them in all cases.
		storageOrPreimageMetaKeys = append(storageOrPreimageMetaKeys, sk)

	}

	// Deserialize services.
	for _, serviceKey := range serviceKeys {
		if err := deserializeService(&deserializedState, serviceKey, serializedState[serviceKey]); err != nil {
			return deserializedState, err
		}
	}

	// Deserialize preimage lookup keys.

	for _, preimageLookupKey := range preimageLookupKeys {
		if err := deserializePreimageLookup(&deserializedState, preimageLookupKey, serializedState[preimageLookupKey]); err != nil {
			return deserializedState, err
		}
	}

	// Deserialize storage or preimage meta keys, these just get put into the global kv items map.
	for _, storageOrPreimageMetaKey := range storageOrPreimageMetaKeys {
		if err := deserializeStorageOrPreimageMeta(&deserializedState, storageOrPreimageMetaKey, serializedState[storageOrPreimageMetaKey]); err != nil {
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
	encodedServiceAccount := encodedServiceAccount{}
	if err := jam.Unmarshal(encodedValue, &encodedServiceAccount); err != nil {
		return fmt.Errorf("deserialize service: error unmarshalling: %w", err)
	}

	serviceAccount := service.ServiceAccount{
		CodeHash:                       encodedServiceAccount.CodeHash,
		Balance:                        encodedServiceAccount.Balance,
		GasLimitForAccumulator:         encodedServiceAccount.GasLimitForAccumulator,
		GasLimitOnTransfer:             encodedServiceAccount.GasLimitOnTransfer,
		GratisStorageOffset:            encodedServiceAccount.GratisStorageOffset,
		CreationTimeslot:               encodedServiceAccount.CreationTimeslot,
		MostRecentAccumulationTimeslot: encodedServiceAccount.MostRecentAccumulationTimeslot,
		ParentService:                  encodedServiceAccount.ParentService,
	}

	// Deserialize the footprint.
	serviceAccount.SetTotalNumberOfItems(encodedServiceAccount.FootprintItems)
	serviceAccount.SetTotalNumberOfOctets(encodedServiceAccount.FootprintStorage)

	state.Services[serviceId] = serviceAccount

	return nil
}

// deserializePreimageLookup deserializes a preimage lookup from the given state key and encoded value.
// The original preimage lookup hash is found by simply hashing the decoded value.
func deserializePreimageLookup(state *state.State, sk statekey.StateKey, encodedValue []byte) error {
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

func deserializeStorageOrPreimageMeta(state *state.State, sk statekey.StateKey, encodedValue []byte) error {
	serviceId, _, err := sk.ExtractServiceIDHash()
	if err != nil {
		return fmt.Errorf("deserialize storage or preimage meta: error extracting service ID: %w", err)
	}

	if state.Services == nil {
		return fmt.Errorf("deserializing storage or preimage meta: services map empty")
	}

	serviceAccount, ok := state.Services[serviceId]
	if !ok {
		return fmt.Errorf("deserializing storage or preimage meta: service ID '%v' does not exist", serviceId)
	}

	globalKVItems := serviceAccount.GetGlobalKVItems()
	if globalKVItems == nil {
		globalKVItems = map[statekey.StateKey][]byte{}

	}
	globalKVItems[sk] = encodedValue
	serviceAccount.SetGlobalKVItems(globalKVItems)

	state.Services[serviceId] = serviceAccount

	return nil
}
