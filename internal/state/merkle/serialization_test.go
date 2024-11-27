package state

import (
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/safrole"
	"github.com/eigerco/strawberry/pkg/serialization/codec/jam"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestSerializeState(t *testing.T) {
	// Generate random state
	state := RandomState(t)

	// Serialize and log serialized keys
	encodedState, err := SerializeState(state)
	require.NoError(t, err)

	// Deserialize and check results
	decodedState, err := DeserializeState(encodedState)
	require.NoError(t, err)

	// Compare services
	assert.Equal(t, len(state.Services), len(decodedState.Services),
		"Service map length mismatch (Original: %d, Decoded: %d)",
		len(state.Services), len(decodedState.Services))

	for serviceID, originalService := range state.Services {
		decodedService, exists := decodedState.Services[serviceID]
		if !exists {
			t.Errorf("Service ID %d missing in decoded state. Original service details: %+v",
				serviceID, originalService)
			continue
		}

		assert.Equal(t, originalService.CodeHash, decodedService.CodeHash)
		assert.Equal(t, originalService.Balance, decodedService.Balance)
		assert.Equal(t, originalService.GasLimitForAccumulator, decodedService.GasLimitForAccumulator)
		assert.Equal(t, originalService.GasLimitOnTransfer, decodedService.GasLimitOnTransfer)
	}

	// Check for extra services in decoded state
	for serviceID := range decodedState.Services {
		if _, exists := state.Services[serviceID]; !exists {
			t.Errorf("Extra service ID %d found in decoded state", serviceID)
		}
	}

	// Compare Past Judgements
	assert.Equal(t, sortByteSlicesCopy(state.PastJudgements.GoodWorkReports), decodedState.PastJudgements.GoodWorkReports, "GoodWorkReports mismatch")
	assert.Equal(t, sortByteSlicesCopy(state.PastJudgements.BadWorkReports), decodedState.PastJudgements.BadWorkReports, "BadWorkReports mismatch")
	assert.Equal(t, sortByteSlicesCopy(state.PastJudgements.WonkyWorkReports), decodedState.PastJudgements.WonkyWorkReports, "WonkyWorkReports mismatch")
	assert.Equal(t, sortByteSlicesCopy(state.PastJudgements.OffendingValidators), decodedState.PastJudgements.OffendingValidators, "OffendingValidators mismatch")

	// Compare Accumulation Queue and History
	assert.Equal(t, state.AccumulationQueue, decodedState.AccumulationQueue, "AccumulationQueue mismatch")
	assert.Equal(t, state.AccumulationHistory, decodedState.AccumulationHistory, "AccumulationHistory mismatch")
}

func TestSerializeSafroleState(t *testing.T) {
	testCases := []struct {
		name                 string
		generateSafroleState func(t *testing.T) safrole.State
	}{
		{
			name:                 "WithTicketBodies",
			generateSafroleState: RandomSafroleStateWithTicketBodies,
		},
		{
			name:                 "WithEpochKeys",
			generateSafroleState: RandomSafroleStateWithEpochKeys,
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			safroleState := tc.generateSafroleState(t)

			encodedValue, err := jam.Marshal(safroleState)
			require.NoError(t, err)

			var decodedValue safrole.State

			err = jam.Unmarshal(encodedValue, &decodedValue)
			require.NoError(t, err)

			require.Equal(t, safroleState, decodedValue, "safrole state mismatch")
		})
	}
}

// TestSerializeStateCoreAuthorizersPool checks the serialization of the CoreAuthorizersPool field.
func TestSerializeStateCoreAuthorizersPool(t *testing.T) {
	state := RandomState(t)
	serializedState, err := SerializeState(state)
	require.NoError(t, err)

	stateKey := generateStateKeyBasic(1)
	hashKey := crypto.Hash(stateKey)
	assert.Contains(t, serializedState, hashKey)
	assert.NotEmpty(t, serializedState[hashKey])
}

// TestSerializeStatePendingAuthorizersQueues checks the serialization of the PendingAuthorizersQueues field.
func TestSerializeStatePendingAuthorizersQueues(t *testing.T) {
	state := RandomState(t)
	serializedState, err := SerializeState(state)
	require.NoError(t, err)

	stateKey := generateStateKeyBasic(2)
	hashKey := crypto.Hash(stateKey)
	assert.Contains(t, serializedState, hashKey)
	assert.NotEmpty(t, serializedState[hashKey])
}

// TestSerializeStateRecentBlocks checks the serialization of the RecentBlocks field.
func TestSerializeStateRecentBlocks(t *testing.T) {
	state := RandomState(t)
	serializedState, err := SerializeState(state)
	require.NoError(t, err)

	stateKey := generateStateKeyBasic(3)
	hashKey := crypto.Hash(stateKey)
	assert.Contains(t, serializedState, hashKey)
	assert.NotEmpty(t, serializedState[hashKey])
}

// TestSerializeStateValidatorState checks the serialization of the ValidatorState fields.
func TestSerializeStateValidatorState(t *testing.T) {
	state := RandomState(t)
	serializedState, err := SerializeState(state)
	require.NoError(t, err)

	stateKey := generateStateKeyBasic(4)
	hashKey := crypto.Hash(stateKey)
	assert.Contains(t, serializedState, hashKey)
	assert.NotEmpty(t, serializedState[hashKey])
}

// TestSerializeStatePastJudgements checks the serialization of the PastJudgements field.
func TestSerializeStatePastJudgements(t *testing.T) {
	state := RandomState(t)
	serializedState, err := SerializeState(state)
	require.NoError(t, err)

	stateKey := generateStateKeyBasic(5)
	hashKey := crypto.Hash(stateKey)
	assert.Contains(t, serializedState, hashKey)
	assert.NotEmpty(t, serializedState[hashKey])
}

// TestSerializeStateEntropyPool checks the serialization of the EntropyPool field.
func TestSerializeStateEntropyPool(t *testing.T) {
	state := RandomState(t)
	serializedState, err := SerializeState(state)
	require.NoError(t, err)

	stateKey := generateStateKeyBasic(6)
	hashKey := crypto.Hash(stateKey)
	assert.Contains(t, serializedState, hashKey)
	assert.NotEmpty(t, serializedState[hashKey])
}

// TestSerializeStateFutureValidators checks the serialization of the FutureValidators field.
func TestSerializeStateFutureValidators(t *testing.T) {
	state := RandomState(t)
	serializedState, err := SerializeState(state)
	require.NoError(t, err)

	stateKey := generateStateKeyBasic(7)
	hashKey := crypto.Hash(stateKey)
	assert.Contains(t, serializedState, hashKey)
	assert.NotEmpty(t, serializedState[hashKey])
}

// TestSerializeStateCurrentValidators checks the serialization of the CurrentValidators field.
func TestSerializeStateCurrentValidators(t *testing.T) {
	state := RandomState(t)
	serializedState, err := SerializeState(state)
	require.NoError(t, err)

	stateKey := generateStateKeyBasic(8)
	hashKey := crypto.Hash(stateKey)
	assert.Contains(t, serializedState, hashKey)
	assert.NotEmpty(t, serializedState[hashKey])
}

// TestSerializeStatePreviousValidators checks the serialization of the PreviousValidators field.
func TestSerializeStatePreviousValidators(t *testing.T) {
	state := RandomState(t)
	serializedState, err := SerializeState(state)
	require.NoError(t, err)

	stateKey := generateStateKeyBasic(9)
	hashKey := crypto.Hash(stateKey)
	assert.Contains(t, serializedState, hashKey)
	assert.NotEmpty(t, serializedState[hashKey])
}

// TestSerializeStateCoreAssignments checks the serialization of the CoreAssignments field.
func TestSerializeStateCoreAssignments(t *testing.T) {
	state := RandomState(t)
	serializedState, err := SerializeState(state)
	require.NoError(t, err)

	stateKey := generateStateKeyBasic(10)
	hashKey := crypto.Hash(stateKey)
	assert.Contains(t, serializedState, hashKey)
	assert.NotEmpty(t, serializedState[hashKey])
}

// TestSerializeStateTimeslotIndex checks the serialization of the TimeslotIndex field.
func TestSerializeStateTimeslotIndex(t *testing.T) {
	state := RandomState(t)
	serializedState, err := SerializeState(state)
	require.NoError(t, err)

	stateKey := generateStateKeyBasic(11)
	hashKey := crypto.Hash(stateKey)
	assert.Contains(t, serializedState, hashKey)
	assert.NotEmpty(t, serializedState[hashKey])
}

// TestSerializeStatePrivilegedServices checks the serialization of the PrivilegedServices field.
func TestSerializeStatePrivilegedServices(t *testing.T) {
	state := RandomState(t)
	serializedState, err := SerializeState(state)
	require.NoError(t, err)

	stateKey := generateStateKeyBasic(12)
	hashKey := crypto.Hash(stateKey)
	assert.Contains(t, serializedState, hashKey)
	assert.NotEmpty(t, serializedState[hashKey])
}

// TestSerializeStateValidatorStatistics checks the serialization of the ValidatorStatistics field.
func TestSerializeStateValidatorStatistics(t *testing.T) {
	state := RandomState(t)
	serializedState, err := SerializeState(state)
	require.NoError(t, err)

	stateKey := generateStateKeyBasic(13)
	hashKey := crypto.Hash(stateKey)
	assert.Contains(t, serializedState, hashKey)
	assert.NotEmpty(t, serializedState[hashKey])
}

// TestSerializeStateAccumulatedQueue checks the serialization of the AccumulatedQueue field.
func TestSerializeStateAccumulatedQueue(t *testing.T) {
	state := RandomState(t)
	serializedState, err := SerializeState(state)
	require.NoError(t, err)

	stateKey := generateStateKeyBasic(14)
	hashKey := crypto.Hash(stateKey)
	assert.Contains(t, serializedState, hashKey)
	assert.NotEmpty(t, serializedState[hashKey])
}

// TestSerializeStateAccumulatedHistory checks the serialization of the AccumulatedHistory field.
func TestSerializeStateAccumulatedHistory(t *testing.T) {
	state := RandomState(t)
	serializedState, err := SerializeState(state)
	require.NoError(t, err)

	stateKey := generateStateKeyBasic(15)
	hashKey := crypto.Hash(stateKey)
	assert.Contains(t, serializedState, hashKey)
	assert.NotEmpty(t, serializedState[hashKey])
}

// TestSerializeStateServices checks the serialization of the Services field.
func TestSerializeStateServices(t *testing.T) {
	state := RandomState(t)
	serializedState, err := SerializeState(state)
	require.NoError(t, err)

	for serviceId := range state.Services {
		stateKey := generateStateKeyInterleavedBasic(255, serviceId)
		hashKey := crypto.Hash(stateKey)
		assert.Contains(t, serializedState, hashKey)
		assert.NotEmpty(t, serializedState[hashKey])
	}
}
