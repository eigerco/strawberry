package merkle

import (
	"math"

	"github.com/eigerco/strawberry/internal/block"
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/service"
	"github.com/eigerco/strawberry/internal/state"
	"github.com/eigerco/strawberry/pkg/serialization/codec/jam"
)

// SerializeState serializes the given state into a map of state keys to byte arrays, for merklization.
// Graypaper 0.5.4.
func SerializeState(s state.State) (map[state.StateKey][]byte, error) {
	serializedState := make(map[state.StateKey][]byte)

	// Helper function to serialize individual fields
	serializeField := func(key uint8, value interface{}) error {
		stateKey := generateStateKeyBasic(key)
		encodedValue, err := jam.Marshal(value)
		if err != nil {
			return err
		}
		serializedState[stateKey] = encodedValue
		return nil
	}

	// Serialize basic fields
	basicFields := []struct {
		key   uint8
		value interface{}
	}{
		{1, s.CoreAuthorizersPool},
		{2, s.PendingAuthorizersQueues},
		{3, s.RecentBlocks},
		{6, s.EntropyPool},
		{7, s.ValidatorState.QueuedValidators},
		{8, s.ValidatorState.CurrentValidators},
		{9, s.ValidatorState.ArchivedValidators},
		{10, s.CoreAssignments},
		{11, s.TimeslotIndex},
		{12, s.PrivilegedServices},
		{13, s.ActivityStatistics},
		{14, s.AccumulationQueue},
		{15, s.AccumulationHistory},
	}

	for _, field := range basicFields {
		if err := serializeField(field.key, field.value); err != nil {
			return nil, err
		}
	}

	// Serialize SafroleState specific fields
	if err := serializeSafroleState(s, serializedState); err != nil {
		return nil, err
	}

	// Serialize Past Judgements
	if err := serializeJudgements(s, serializedState); err != nil {
		return nil, err
	}

	// Serialize Services
	for serviceId, serviceAccount := range s.Services {
		if err := serializeServiceAccount(serviceId, serviceAccount, serializedState); err != nil {
			return nil, err
		}
	}

	return serializedState, nil
}

func serializeSafroleState(state state.State, serializedState map[state.StateKey][]byte) error {
	encodedSafroleState, err := jam.Marshal(state.ValidatorState.SafroleState)
	if err != nil {
		return err
	}

	stateKey := generateStateKeyBasic(4)
	serializedState[stateKey] = encodedSafroleState
	return nil
}

func serializeJudgements(state state.State, serializedState map[state.StateKey][]byte) error {
	sortedGoodWorkReports := sortByteSlicesCopy(state.PastJudgements.GoodWorkReports)
	encodedGoodWorkReports, err := jam.Marshal(sortedGoodWorkReports)
	if err != nil {
		return err
	}
	encodedBadWorkReports, err := jam.Marshal(sortByteSlicesCopy(state.PastJudgements.BadWorkReports))
	if err != nil {
		return err
	}
	encodedWonkyWorkReports, err := jam.Marshal(sortByteSlicesCopy(state.PastJudgements.WonkyWorkReports))
	if err != nil {
		return err
	}
	encodedOffendingValidators, err := jam.Marshal(sortByteSlicesCopy(state.PastJudgements.OffendingValidators))
	if err != nil {
		return err
	}

	combined := combineEncoded(
		encodedGoodWorkReports,
		encodedBadWorkReports,
		encodedWonkyWorkReports,
		encodedOffendingValidators,
	)
	stateKey := generateStateKeyBasic(5)
	serializedState[stateKey] = combined
	return nil
}

func serializeServiceAccount(serviceId block.ServiceId, serviceAccount service.ServiceAccount, serializedState map[state.StateKey][]byte) error {
	encodedCodeHash, err := jam.Marshal(serviceAccount.CodeHash)
	if err != nil {
		return err
	}
	encodedBalance, err := jam.Marshal(serviceAccount.Balance)
	if err != nil {
		return err
	}
	encodedGasLimitForAccumulator, err := jam.Marshal(serviceAccount.GasLimitForAccumulator)
	if err != nil {
		return err
	}
	encodedGasLimitOnTransfer, err := jam.Marshal(serviceAccount.GasLimitOnTransfer)
	if err != nil {
		return err
	}

	totalFootprintSize := calculateFootprintSize(serviceAccount.Storage, serviceAccount.PreimageMeta) // ao graypaper 0.5.4
	encodedFootprintSize, err := jam.Marshal(totalFootprintSize)
	if err != nil {
		return err
	}

	footprintItems := 2*len(serviceAccount.PreimageMeta) + len(serviceAccount.Storage)
	encodedFootprintItems, err := jam.Marshal(footprintItems)
	if err != nil {
		return err
	}

	combined := combineEncoded(
		encodedCodeHash,
		encodedBalance,
		encodedGasLimitForAccumulator,
		encodedGasLimitOnTransfer,
		encodedFootprintSize,
		encodedFootprintItems,
	)
	stateKey, err := generateStateKeyInterleavedBasic(255, serviceId)
	if err != nil {
		return err
	}
	serializedState[stateKey] = combined

	// Serialize storage and preimage items
	if err := serializeStorageAndPreimage(serviceId, serviceAccount, serializedState); err != nil {
		return err
	}

	return nil
}

func serializeStorageAndPreimage(serviceId block.ServiceId, serviceAccount service.ServiceAccount, serializedState map[state.StateKey][]byte) error {
	encodedMaxUint32, err := jam.Marshal(math.MaxUint32)
	if err != nil {
		return err
	}
	for hash, value := range serviceAccount.Storage {
		encodedValue, err := jam.Marshal(value)
		if err != nil {
			return err
		}

		var combined stateConstructorHashComponent
		copy(combined[:4], encodedMaxUint32)
		copy(combined[4:], hash[:28])
		stateKey, err := generateStateKeyInterleaved(serviceId, combined)
		if err != nil {
			return err
		}
		serializedState[stateKey] = encodedValue
	}

	encodedMaxUint32MinusOne, err := jam.Marshal(math.MaxUint32 - 1)
	if err != nil {
		return err
	}
	for hash, value := range serviceAccount.PreimageLookup {
		encodedValue, err := jam.Marshal(value)
		if err != nil {
			return err
		}

		var combined stateConstructorHashComponent
		copy(combined[:4], encodedMaxUint32MinusOne)
		copy(combined[4:], hash[1:29])
		stateKey, err := generateStateKeyInterleaved(serviceId, combined)
		if err != nil {
			return err
		}
		serializedState[stateKey] = encodedValue
	}

	for key, preImageHistoricalTimeslots := range serviceAccount.PreimageMeta {
		encodedLength, err := jam.Marshal(key.Length)
		if err != nil {
			return err
		}
		encodedPreImageHistoricalTimeslots, err := jam.Marshal(preImageHistoricalTimeslots)
		if err != nil {
			return err
		}
		hashedPreImageHistoricalTimeslots := crypto.HashData(encodedPreImageHistoricalTimeslots)

		var combined stateConstructorHashComponent
		copy(combined[:4], encodedLength)
		copy(combined[4:], hashedPreImageHistoricalTimeslots[2:30])
		stateKey, err := generateStateKeyInterleaved(serviceId, combined)
		if err != nil {
			return err
		}
		serializedState[stateKey] = encodedPreImageHistoricalTimeslots
	}
	return nil
}
