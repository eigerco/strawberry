package serialization

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/eigerco/strawberry/internal/safrole"
	"github.com/eigerco/strawberry/internal/state/serialization/statekey"
	"github.com/eigerco/strawberry/pkg/serialization/codec/jam"
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

	stateKey := statekey.NewBasic(1)
	assert.Contains(t, serializedState, stateKey)
	assert.NotEmpty(t, serializedState[stateKey])
}

// TestSerializeStatePendingAuthorizersQueues checks the serialization of the PendingAuthorizersQueues field.
func TestSerializeStatePendingAuthorizersQueues(t *testing.T) {
	state := RandomState(t)
	serializedState, err := SerializeState(state)
	require.NoError(t, err)

	stateKey := statekey.NewBasic(2)
	assert.Contains(t, serializedState, stateKey)
	assert.NotEmpty(t, serializedState[stateKey])
}

// TestSerializeStateRecentBlocks checks the serialization of the RecentBlocks field.
func TestSerializeStateRecentBlocks(t *testing.T) {
	state := RandomState(t)
	serializedState, err := SerializeState(state)
	require.NoError(t, err)

	stateKey := statekey.NewBasic(3)
	assert.Contains(t, serializedState, stateKey)
	assert.NotEmpty(t, serializedState[stateKey])
}

// TestSerializeStateValidatorState checks the serialization of the ValidatorState fields.
func TestSerializeStateValidatorState(t *testing.T) {
	state := RandomState(t)
	serializedState, err := SerializeState(state)
	require.NoError(t, err)

	stateKey := statekey.NewBasic(4)
	assert.Contains(t, serializedState, stateKey)
	assert.NotEmpty(t, serializedState[stateKey])
}

// TestSerializeStatePastJudgements checks the serialization of the PastJudgements field.
func TestSerializeStatePastJudgements(t *testing.T) {
	state := RandomState(t)
	serializedState, err := SerializeState(state)
	require.NoError(t, err)

	hashKey := statekey.NewBasic(5)
	assert.Contains(t, serializedState, hashKey)
	assert.NotEmpty(t, serializedState[hashKey])
}

// TestSerializeStateEntropyPool checks the serialization of the EntropyPool field.
func TestSerializeStateEntropyPool(t *testing.T) {
	state := RandomState(t)
	serializedState, err := SerializeState(state)
	require.NoError(t, err)

	stateKey := statekey.NewBasic(6)
	assert.Contains(t, serializedState, stateKey)
	assert.NotEmpty(t, serializedState[stateKey])
}

// TestSerializeStateFutureValidators checks the serialization of the FutureValidators field.
func TestSerializeStateFutureValidators(t *testing.T) {
	state := RandomState(t)
	serializedState, err := SerializeState(state)
	require.NoError(t, err)

	stateKey := statekey.NewBasic(7)
	assert.Contains(t, serializedState, stateKey)
	assert.NotEmpty(t, serializedState[stateKey])
}

// TestSerializeStateCurrentValidators checks the serialization of the CurrentValidators field.
func TestSerializeStateCurrentValidators(t *testing.T) {
	state := RandomState(t)
	serializedState, err := SerializeState(state)
	require.NoError(t, err)

	stateKey := statekey.NewBasic(8)
	assert.Contains(t, serializedState, stateKey)
	assert.NotEmpty(t, serializedState[stateKey])
}

// TestSerializeStatePreviousValidators checks the serialization of the PreviousValidators field.
func TestSerializeStatePreviousValidators(t *testing.T) {
	state := RandomState(t)
	serializedState, err := SerializeState(state)
	require.NoError(t, err)

	hashKey := statekey.NewBasic(9)
	assert.Contains(t, serializedState, hashKey)
	assert.NotEmpty(t, serializedState[hashKey])
}

// TestSerializeStateCoreAssignments checks the serialization of the CoreAssignments field.
func TestSerializeStateCoreAssignments(t *testing.T) {
	state := RandomState(t)
	serializedState, err := SerializeState(state)
	require.NoError(t, err)

	stateKey := statekey.NewBasic(10)
	assert.Contains(t, serializedState, stateKey)
	assert.NotEmpty(t, serializedState[stateKey])
}

// TestSerializeStateTimeslotIndex checks the serialization of the TimeslotIndex field.
func TestSerializeStateTimeslotIndex(t *testing.T) {
	state := RandomState(t)
	serializedState, err := SerializeState(state)
	require.NoError(t, err)

	stateKey := statekey.NewBasic(11)
	assert.Contains(t, serializedState, stateKey)
	assert.NotEmpty(t, serializedState[stateKey])
}

// TestSerializeStatePrivilegedServices checks the serialization of the PrivilegedServices field.
func TestSerializeStatePrivilegedServices(t *testing.T) {
	state := RandomState(t)
	serializedState, err := SerializeState(state)
	require.NoError(t, err)

	stateKey := statekey.NewBasic(12)
	assert.Contains(t, serializedState, stateKey)
	assert.NotEmpty(t, serializedState[stateKey])
}

// TestSerializeStateValidatorStatistics checks the serialization of the ValidatorStatistics field.
func TestSerializeStateValidatorStatistics(t *testing.T) {
	state := RandomState(t)
	serializedState, err := SerializeState(state)
	require.NoError(t, err)

	stateKey := statekey.NewBasic(13)
	assert.Contains(t, serializedState, stateKey)
	assert.NotEmpty(t, serializedState[stateKey])
}

// TestSerializeStateAccumulatedQueue checks the serialization of the AccumulatedQueue field.
func TestSerializeStateAccumulatedQueue(t *testing.T) {
	state := RandomState(t)
	serializedState, err := SerializeState(state)
	require.NoError(t, err)

	hashKey := statekey.NewBasic(14)
	assert.Contains(t, serializedState, hashKey)
	assert.NotEmpty(t, serializedState[hashKey])
}

// TestSerializeStateAccumulatedHistory checks the serialization of the AccumulatedHistory field.
func TestSerializeStateAccumulatedHistory(t *testing.T) {
	state := RandomState(t)
	serializedState, err := SerializeState(state)
	require.NoError(t, err)

	stateKey := statekey.NewBasic(15)
	assert.Contains(t, serializedState, stateKey)
	assert.NotEmpty(t, serializedState[stateKey])
}

// TestSerializeStateServices checks the serialization of the Services field.
func TestSerializeStateServices(t *testing.T) {
	state := RandomState(t)
	serializedState, err := SerializeState(state)
	require.NoError(t, err)

	for serviceId := range state.Services {
		hashKey, err := statekey.NewService(serviceId)
		require.NoError(t, err)
		assert.Contains(t, serializedState, hashKey)
		assert.NotEmpty(t, serializedState[hashKey])
	}
}

// TestCombineEncoded verifies that combining multiple encoded fields works as expected.
func TestCombineEncoded(t *testing.T) {
	field1 := []byte{0x01, 0x02}
	field2 := []byte{0x03, 0x04}

	// Combine the fields
	combined := combineEncoded(field1, field2)

	// Verify the combined result
	assert.Equal(t, []byte{0x01, 0x02, 0x03, 0x04}, combined)
}
