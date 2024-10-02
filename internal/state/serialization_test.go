package state

import (
	"fmt"
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/safrole"
	"github.com/eigerco/strawberry/pkg/serialization"
	"github.com/eigerco/strawberry/pkg/serialization/codec"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestSerializeState(t *testing.T) {
	// Step 1: Generate random state and serialize it
	state := RandomState(t)
	encodedState, err := SerializeState(state)
	require.NoError(t, err)

	// Step 2: Deserialize the serialized state
	decodedState, err := DeserializeState(encodedState)
	assert.NoError(t, err)
	assert.NotEmpty(t, decodedState)

	// Step 3: Compare the deserialized state with the original state

	// Compare CoreAuthorizersPool
	assert.Equal(t, state.CoreAuthorizersPool, decodedState.CoreAuthorizersPool, "CoreAuthorizersPool mismatch")

	// Compare PendingAuthorizersQueues
	assert.Equal(t, state.PendingAuthorizersQueues, decodedState.PendingAuthorizersQueues, "PendingAuthorizersQueues mismatch")

	// Compare RecentBlocks
	assert.Equal(t, state.RecentBlocks, decodedState.RecentBlocks, "RecentBlocks mismatch")

	// Compare ValidatorState fields
	assert.Equal(t, state.ValidatorState.SafroleState.NextValidators, decodedState.ValidatorState.SafroleState.NextValidators, "NextValidators mismatch")
	assert.Equal(t, state.ValidatorState.CurrentValidators, decodedState.ValidatorState.CurrentValidators, "CurrentValidators mismatch")
	assert.Equal(t, state.ValidatorState.QueuedValidators, decodedState.ValidatorState.QueuedValidators, "FutureValidators mismatch")
	assert.Equal(t, state.ValidatorState.ArchivedValidators, decodedState.ValidatorState.ArchivedValidators, "PreviousValidators mismatch")
	assert.Equal(t, state.ValidatorState.SafroleState.RingCommitment, decodedState.ValidatorState.SafroleState.RingCommitment, "RingCommitment mismatch")

	// Ensure SealingKeySeries is correctly deserialized
	assert.Equal(t, state.ValidatorState.SafroleState.SealingKeySeries, decodedState.ValidatorState.SafroleState.SealingKeySeries, "SealingKeySeries mismatch")

	// Compare TicketAccumulator
	assert.Equal(t, state.ValidatorState.SafroleState.TicketAccumulator, decodedState.ValidatorState.SafroleState.TicketAccumulator, "TicketAccumulator mismatch")

	// Compare EntropyPool
	assert.Equal(t, state.EntropyPool, decodedState.EntropyPool, "EntropyPool mismatch")

	// Compare CoreAssignments
	assert.Equal(t, state.CoreAssignments, decodedState.CoreAssignments, "CoreAssignments mismatch")

	// Compare TimeslotIndex
	assert.Equal(t, state.TimeslotIndex, decodedState.TimeslotIndex, "TimeslotIndex mismatch")

	// Compare PrivilegedServices
	assert.Equal(t, state.PrivilegedServices, decodedState.PrivilegedServices, "PrivilegedServices mismatch")

	// Compare ValidatorStatistics
	assert.Equal(t, state.ValidatorStatistics, decodedState.ValidatorStatistics, "ValidatorStatistics mismatch")

	// Compare Services
	assert.Equal(t, len(state.Services), len(decodedState.Services), "Service map length mismatch")
	for serviceID, originalService := range state.Services {
		decodedService, exists := decodedState.Services[serviceID]
		require.True(t, exists, fmt.Sprintf("ServiceID %d missing in decoded state", serviceID))

		// Compare individual fields in ServiceAccount
		assert.Equal(t, originalService.CodeHash, decodedService.CodeHash, fmt.Sprintf("Mismatch in CodeHash for ServiceID %d", serviceID))
		assert.Equal(t, originalService.Balance, decodedService.Balance, fmt.Sprintf("Mismatch in Balance for ServiceID %d", serviceID))
		assert.Equal(t, originalService.GasLimitForAccumulator, decodedService.GasLimitForAccumulator, fmt.Sprintf("Mismatch in GasLimitForAccumulator for ServiceID %d", serviceID))
		assert.Equal(t, originalService.GasLimitOnTransfer, decodedService.GasLimitOnTransfer, fmt.Sprintf("Mismatch in GasLimitOnTransfer for ServiceID %d", serviceID))

	}

	// Compare Past Judgements
	assert.Equal(t, sortByteSlicesCopy(state.PastJudgements.GoodWorkReports), decodedState.PastJudgements.GoodWorkReports, "GoodWorkReports mismatch")
	assert.Equal(t, sortByteSlicesCopy(state.PastJudgements.BadWorkReports), decodedState.PastJudgements.BadWorkReports, "BadWorkReports mismatch")
	assert.Equal(t, sortByteSlicesCopy(state.PastJudgements.WonkyWorkReports), decodedState.PastJudgements.WonkyWorkReports, "WonkyWorkReports mismatch")
	assert.Equal(t, sortByteSlicesCopy(state.PastJudgements.OffendingValidators), decodedState.PastJudgements.OffendingValidators, "OffendingValidators mismatch")
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

			jamCodec := codec.NewJamCodec()
			serializer := serialization.NewSerializer(jamCodec)

			encodedValue, err := serializer.Encode(safroleState)
			require.NoError(t, err)

			var decodedValue safrole.State

			err = serializer.Decode(encodedValue, &decodedValue)
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

// TestSerializeStateServices checks the serialization of the Services field.
func TestSerializeStateServices(t *testing.T) {
	state := RandomState(t)
	serializedState, err := SerializeState(state)
	require.NoError(t, err)

	for serviceId := range state.Services {
		stateKey := generateStateKey(255, serviceId)
		hashKey := crypto.Hash(stateKey)
		assert.Contains(t, serializedState, hashKey)
		assert.NotEmpty(t, serializedState[hashKey])
	}
}

// TestSerializeStateStorage checks the serialization of storage items within services.
func TestSerializeStateStorage(t *testing.T) {
	state := RandomState(t)
	serializedState, err := SerializeState(state)
	require.NoError(t, err)

	for serviceId, serviceAccount := range state.Services {
		for hash := range serviceAccount.Storage {
			stateKey := generateStateKeyInterleaved(serviceId, hash)
			hashKey := crypto.Hash(stateKey)
			assert.Contains(t, serializedState, hashKey)
			assert.NotEmpty(t, serializedState[hashKey])
		}
	}
}

// TestSerializeStatePreimageMeta checks the serialization of the preimage metadata within services.
func TestSerializeStatePreimageMeta(t *testing.T) {
	state := RandomState(t)
	serializedState, err := SerializeState(state)
	require.NoError(t, err)

	for serviceId, serviceAccount := range state.Services {
		for key := range serviceAccount.PreimageMeta {
			stateKey := generateStateKeyInterleaved(serviceId, key.Hash)
			hashKey := crypto.Hash(stateKey)
			assert.Contains(t, serializedState, hashKey)
			assert.NotEmpty(t, serializedState[hashKey])
		}
	}
}
