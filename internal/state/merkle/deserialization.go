package merkle

import (
	"fmt"

	"github.com/eigerco/strawberry/internal/block"
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/service"
	"github.com/eigerco/strawberry/internal/state"
	"github.com/eigerco/strawberry/pkg/serialization/codec/jam"
)

// DeserializeState deserializes the given map of state keys to byte slices into a State object. Not possible to restore the full state.
func DeserializeState(serializedState map[state.StateKey][]byte) (state.State, error) {
	deserializedState := state.State{}

	// Helper function to deserialize individual fields
	deserializeField := func(key uint8, target interface{}) error {
		stateKey := generateStateKeyBasic(key)
		encodedValue, ok := serializedState[stateKey]
		if !ok {
			return fmt.Errorf("missing state key %v", key)
		}
		return jam.Unmarshal(encodedValue, target)
	}

	// Deserialize basic fields
	basicFields := []struct {
		key   uint8
		value interface{}
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

	// Deserialize Services
	if err := deserializeServices(&deserializedState, serializedState); err != nil {
		return deserializedState, err
	}

	return deserializedState, nil
}

func deserializeServices(state *state.State, serializedState map[state.StateKey][]byte) error {
	state.Services = make(service.ServiceState)

	// Iterate over serializedState and look for service entries (identified by prefix 255)
	for stateKey, encodedValue := range serializedState {
		// Check if this is a service account entry (state key starts with 255)
		if isServiceAccountKey(stateKey) {
			// Extract service ID from the key
			serviceId, err := extractServiceIdFromKey(stateKey)
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
				FootprintItems         int
			}
			if err := jam.Unmarshal(encodedValue, &combined); err != nil {
				return err
			}

			// Create and populate the ServiceAccount from the deserialized data
			serviceAccount := service.ServiceAccount{
				CodeHash:               combined.CodeHash,
				Balance:                combined.Balance,
				GasLimitForAccumulator: combined.GasLimitForAccumulator,
				GasLimitOnTransfer:     combined.GasLimitOnTransfer,
			}

			// We cannot completely deserialize storage and preimage items. That's why they are not here.

			// Add the deserialized service account to the state
			state.Services[serviceId] = serviceAccount
		}
	}

	return nil
}

func isServiceAccountKey(stateKey state.StateKey) bool {
	// Check if the first byte of the state key is 255 (which identifies service keys)
	return stateKey[0] == 255
}

func extractServiceIdFromKey(stateKey state.StateKey) (block.ServiceId, error) {
	// Collect service ID bytes from positions 1,3,5,7 into a slice
	encodedServiceId := []byte{
		stateKey[1],
		stateKey[3],
		stateKey[5],
		stateKey[7],
	}

	var serviceId block.ServiceId
	if err := jam.Unmarshal(encodedServiceId, &serviceId); err != nil {
		return 0, err
	}

	return serviceId, nil
}
