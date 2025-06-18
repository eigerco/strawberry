package serialization

import (
	"fmt"

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
	var serviceKeys []statekey.StateKey
	for sk := range serializedState {
		if sk.IsChapterKey() {
			continue
		}
		if sk.IsServiceKey() {
			serviceKeys = append(serviceKeys, sk)
		}
	}

	// Deserialize Services
	for _, serviceKey := range serviceKeys {
		if err := deserializeService(&deserializedState, serviceKey, serializedState[serviceKey]); err != nil {
			return deserializedState, err
		}
	}

	// TODO deserializing preimage lookup, preimage meta and storage keys
	// requires a change to how we store service dicts. They should all be
	// stored in a single dict, and as the host we shouldn't care about knowing
	// which key is which, as long as each host call can read and write it's
	// value. This requires a reasonable refactor, but until then, given 0.6.7
	// changes, we can no longer tell storage keys apart from preimage meta
	// keys.
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

	state.Services[serviceId] = serviceAccount

	return nil
}
