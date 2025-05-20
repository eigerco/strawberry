package serialization

import (
	"bytes"
	"crypto/ed25519"
	"slices"
	"sort"

	"github.com/eigerco/strawberry/internal/block"
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/service"
	"github.com/eigerco/strawberry/internal/state"
	"github.com/eigerco/strawberry/internal/state/serialization/statekey"
	"github.com/eigerco/strawberry/pkg/serialization/codec/jam"
)

// SerializeState serializes the given state into a map of state keys to byte arrays, for merklization.
// Graypaper 0.5.4.
func SerializeState(s state.State) (map[statekey.StateKey][]byte, error) {
	serializedState := make(map[statekey.StateKey][]byte)

	// Helper function to serialize individual fields
	serializeField := func(key uint8, value interface{}) error {
		stateKey := statekey.NewBasic(key)
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

func serializeServiceAccount(serviceId block.ServiceId, serviceAccount service.ServiceAccount, serializedState map[statekey.StateKey][]byte) error {
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
	stateKey, err := statekey.NewService(serviceId)
	if err != nil {
		return err
	}
	serializedState[stateKey] = encodedServiceValue

	if err := serializeStorage(serviceAccount.Storage, serializedState); err != nil {
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

func serializeStorage(storage map[statekey.StateKey][]byte, serializedState map[statekey.StateKey][]byte) error {
	for stateKey, value := range storage {

		// Storage keys are state keys. This allows deserialization
		// later since state key creation for them is lossy. The PVM code knows
		// the actual key it wants, as long as we always "hash" it into a state
		// key in the same way we can always retrieve it again.
		serializedState[stateKey] = value
	}

	return nil
}

func serializePreimageLookup(serviceId block.ServiceId, preimages map[crypto.Hash][]byte, serializedState map[statekey.StateKey][]byte) error {

	for hash, value := range preimages {
		stateKey, err := statekey.NewPreimageLookup(serviceId, hash)
		if err != nil {
			return err
		}

		serializedState[stateKey] = value
	}

	return nil
}

func serializePreimageMeta(serviceId block.ServiceId, preimageMeta map[service.PreImageMetaKey]service.PreimageHistoricalTimeslots, serializedState map[statekey.StateKey][]byte) error {
	for key, preImageHistoricalTimeslots := range preimageMeta {
		encodedPreImageHistoricalTimeslots, err := jam.Marshal(preImageHistoricalTimeslots)
		if err != nil {
			return err
		}

		stateKey, err := statekey.NewPreimageMeta(serviceId, key.Hash, uint32(key.Length))
		if err != nil {
			return err
		}
		serializedState[stateKey] = encodedPreImageHistoricalTimeslots
	}

	return nil
}

// combineEncoded takes multiple encoded byte arrays and concatenates them into a single byte array.
func combineEncoded(components ...[]byte) []byte {
	var buffer bytes.Buffer

	for _, component := range components {
		buffer.Write(component)
	}

	return buffer.Bytes()
}

// sortByteSlicesCopy returns a sorted copy of a slice of some byte-based types
func sortByteSlicesCopy(slice interface{}) interface{} {
	switch v := slice.(type) {
	case []crypto.Hash:
		// Clone the slice to avoid modifying the original
		copySlice := slices.Clone(v)
		sort.Slice(copySlice, func(i, j int) bool {
			return bytes.Compare(copySlice[i][:], copySlice[j][:]) < 0
		})
		return copySlice
	case []ed25519.PublicKey:
		// Clone the slice to avoid modifying the original
		copySlice := slices.Clone(v)
		sort.Slice(copySlice, func(i, j int) bool {
			return bytes.Compare(copySlice[i], copySlice[j]) < 0
		})
		return copySlice
	default:
		panic("unsupported type for sorting")
	}
}
