package merkle

import (
	"math"

	"github.com/eigerco/strawberry/internal/block"
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/service"
	"github.com/eigerco/strawberry/internal/state"
	"github.com/eigerco/strawberry/pkg/serialization/codec/jam"
)

const (
	// Chapter component for service account state keys.
	ChapterServiceIndex = 255
	// Hash component for storage state keys begins this this value little endian encoded.
	HashStorageIndex = math.MaxUint32 - 1
	// Hash component for preimage lookup state keys begins this this value little endian encoded.
	HashPreimageLookupIndex = math.MaxUint32 - 2
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
		{4, s.ValidatorState.SafroleState},
		{5, s.PastJudgements},
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

	// Serialize Services
	for serviceId, serviceAccount := range s.Services {
		if err := serializeServiceAccount(serviceId, serviceAccount, serializedState); err != nil {
			return nil, err
		}
	}

	return serializedState, nil
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

	encodedTotalStorageSize, err := jam.Marshal(serviceAccount.TotalStorageSize())
	if err != nil {
		return err
	}

	encodedTotalItems, err := jam.Marshal(serviceAccount.TotalItems())
	if err != nil {
		return err
	}

	encodedServiceValue := combineEncoded(
		encodedCodeHash,
		encodedBalance,
		encodedGasLimitForAccumulator,
		encodedGasLimitOnTransfer,
		encodedTotalStorageSize,
		encodedTotalItems,
	)
	stateKey, err := generateStateKeyInterleavedBasic(ChapterServiceIndex, serviceId)
	if err != nil {
		return err
	}
	serializedState[stateKey] = encodedServiceValue

	if err := serializeStorage(serviceId, serviceAccount.Storage, serializedState); err != nil {
		return err
	}

	if err := serializePreimageLookup(serviceId, serviceAccount.PreimageLookup, serializedState); err != nil {
		return err
	}

	if err := serializePreimageMeta(serviceId, serviceAccount.PreimageMeta, serializedState); err != nil {
		return err
	}

	return nil
}

func serializeStorage(serviceId block.ServiceId, storage map[crypto.Hash][]byte, serializedState map[state.StateKey][]byte) error {
	hashIndex, err := jam.Marshal(HashStorageIndex)
	if err != nil {
		return err
	}

	for hash, value := range storage {
		encodedValue, err := jam.Marshal(value)
		if err != nil {
			return err
		}

		var hashComponent stateConstructorHashComponent
		copy(hashComponent[:4], hashIndex)
		copy(hashComponent[4:], hash[:24])
		stateKey, err := generateStateKeyInterleaved(serviceId, hashComponent)
		if err != nil {
			return err
		}
		serializedState[stateKey] = encodedValue
	}

	return nil
}

func serializePreimageLookup(serviceId block.ServiceId, preimages map[crypto.Hash][]byte, serializedState map[state.StateKey][]byte) error {
	hashIndex, err := jam.Marshal(HashPreimageLookupIndex)
	if err != nil {
		return err
	}

	for hash, value := range preimages {
		encodedValue, err := jam.Marshal(value)
		if err != nil {
			return err
		}

		var hashComponent stateConstructorHashComponent
		copy(hashComponent[:4], hashIndex)
		copy(hashComponent[4:], hash[1:25])
		stateKey, err := generateStateKeyInterleaved(serviceId, hashComponent)
		if err != nil {
			return err
		}
		serializedState[stateKey] = encodedValue
	}

	return nil
}

func serializePreimageMeta(serviceId block.ServiceId, preimageMeta map[service.PreImageMetaKey]service.PreimageHistoricalTimeslots, serializedState map[state.StateKey][]byte) error {
	for key, preImageHistoricalTimeslots := range preimageMeta {
		encodedLength, err := jam.Marshal(key.Length)
		if err != nil {
			return err
		}
		encodedPreImageHistoricalTimeslots, err := jam.Marshal(preImageHistoricalTimeslots)
		if err != nil {
			return err
		}
		hashedPreImageHistoricalTimeslots := crypto.HashData(encodedPreImageHistoricalTimeslots)

		var hashComponent stateConstructorHashComponent
		copy(hashComponent[:4], encodedLength)
		copy(hashComponent[4:], hashedPreImageHistoricalTimeslots[2:26])
		stateKey, err := generateStateKeyInterleaved(serviceId, hashComponent)
		if err != nil {
			return err
		}
		serializedState[stateKey] = encodedPreImageHistoricalTimeslots
	}

	return nil
}
