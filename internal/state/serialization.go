package state

import (
	"github.com/eigerco/strawberry/internal/block"
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/pkg/serialization"
	"github.com/eigerco/strawberry/pkg/serialization/codec"
)

// SerializeState serializes the given state into a map of crypto.Hash to byte arrays.
func SerializeState(state State) (map[crypto.Hash][]byte, error) {
	jamCodec := codec.NewJamCodec()
	serializer := serialization.NewSerializer(jamCodec)

	serializedState := make(map[crypto.Hash][]byte)

	// Helper function to serialize individual fields
	serializeField := func(key uint8, value interface{}) error {
		stateKey := generateStateKeyBasic(key)
		encodedValue, err := serializer.Encode(value)
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
		{1, state.CoreAuthorizersPool},
		{2, state.PendingAuthorizersQueues},
		{3, state.RecentBlocks},
		{6, state.EntropyPool},
		{7, state.ValidatorState.QueuedValidators},
		{8, state.ValidatorState.CurrentValidators},
		{9, state.ValidatorState.ArchivedValidators},
		{10, state.CoreAssignments},
		{11, state.TimeslotIndex},
		{12, state.PrivilegedServices},
		{13, state.ValidatorStatistics},
		{14, state.AccumulationQueue},
		{15, state.AccumulationHistory},
	}

	for _, field := range basicFields {
		if err := serializeField(field.key, field.value); err != nil {
			return nil, err
		}
	}

	// Serialize SafroleState specific fields
	if err := serializeSafroleState(state, serializer, serializedState); err != nil {
		return nil, err
	}

	// Serialize Past Judgements
	if err := serializeJudgements(state, serializer, serializedState); err != nil {
		return nil, err
	}

	// Serialize Services
	for serviceId, serviceAccount := range state.Services {
		if err := serializeServiceAccount(serviceId, serviceAccount, serializer, serializedState); err != nil {
			return nil, err
		}
	}

	return serializedState, nil
}

func serializeSafroleState(state State, serializer *serialization.Serializer, serializedState map[crypto.Hash][]byte) error {
	encodedSafroleState, err := serializer.Encode(state.ValidatorState.SafroleState)
	if err != nil {
		return err
	}

	stateKey := generateStateKeyBasic(4)
	serializedState[stateKey] = encodedSafroleState
	return nil
}

func serializeJudgements(state State, serializer *serialization.Serializer, serializedState map[crypto.Hash][]byte) error {
	sortedGoodWorkReports := sortByteSlicesCopy(state.PastJudgements.GoodWorkReports)
	encodedGoodWorkReports, err := serializer.Encode(sortedGoodWorkReports)
	if err != nil {
		return err
	}
	encodedBadWorkReports, err := serializer.Encode(sortByteSlicesCopy(state.PastJudgements.BadWorkReports))
	if err != nil {
		return err
	}
	encodedWonkyWorkReports, err := serializer.Encode(sortByteSlicesCopy(state.PastJudgements.WonkyWorkReports))
	if err != nil {
		return err
	}
	encodedOffendingValidators, err := serializer.Encode(sortByteSlicesCopy(state.PastJudgements.OffendingValidators))
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

func serializeServiceAccount(serviceId block.ServiceId, serviceAccount ServiceAccount, serializer *serialization.Serializer, serializedState map[crypto.Hash][]byte) error {
	encodedCodeHash, err := serializer.Encode(serviceAccount.CodeHash)
	if err != nil {
		return err
	}
	encodedBalance, err := serializer.Encode(serviceAccount.Balance)
	if err != nil {
		return err
	}
	encodedGasLimitForAccumulator, err := serializer.Encode(serviceAccount.GasLimitForAccumulator)
	if err != nil {
		return err
	}
	encodedGasLimitOnTransfer, err := serializer.Encode(serviceAccount.GasLimitOnTransfer)
	if err != nil {
		return err
	}

	totalFootprintSize := calculateFootprintSize(serviceAccount.Storage, serviceAccount.PreimageMeta) // al
	encodedFootprintSize, err := serializer.Encode(totalFootprintSize)
	if err != nil {
		return err
	}

	footprintItems := 2*len(serviceAccount.PreimageMeta) + len(serviceAccount.Storage)
	encodedFootprintItems, err := serializer.Encode(footprintItems)
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
	stateKey := generateStateKey(255, serviceId)
	serializedState[stateKey] = combined

	// Serialize storage and preimage items
	if err := serializeStorageAndPreimage(serviceId, serviceAccount, serializer, serializedState); err != nil {
		return err
	}

	return nil
}

func serializeStorageAndPreimage(serviceId block.ServiceId, serviceAccount ServiceAccount, serializer *serialization.Serializer, serializedState map[crypto.Hash][]byte) error {
	for hash, value := range serviceAccount.Storage {
		encodedValue, err := serializer.Encode(value)
		if err != nil {
			return err
		}
		stateKey := generateStateKeyInterleaved(serviceId, hash)
		serializedState[stateKey] = encodedValue
	}

	for hash, value := range serviceAccount.PreimageLookup {
		encodedValue, err := serializer.Encode(value)
		if err != nil {
			return err
		}
		stateKey := generateStateKeyInterleaved(serviceId, hash)
		serializedState[stateKey] = encodedValue
	}

	for key, preImageHistoricalTimeslots := range serviceAccount.PreimageMeta {
		encodedLength, err := serializer.Encode(key.Length)
		if err != nil {
			return err
		}
		encodedPreImageHistoricalTimeslots, err := serializer.Encode(preImageHistoricalTimeslots)
		if err != nil {
			return err
		}

		var combined [32]byte
		copy(combined[:4], encodedLength)
		hashNotFirst4Bytes := bitwiseNotExceptFirst4Bytes(key.Hash)
		copy(combined[4:], hashNotFirst4Bytes[:])
		stateKey := generateStateKeyInterleaved(serviceId, key.Hash)
		serializedState[stateKey] = encodedPreImageHistoricalTimeslots
	}
	return nil
}
