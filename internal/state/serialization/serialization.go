package serialization

import (
	"bytes"
	"crypto/ed25519"
	"slices"
	"sort"

	"github.com/eigerco/strawberry/internal/block"
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/jamtime"
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
		{3, s.RecentHistory},
		{4, s.ValidatorState.SafroleState},
		{5, s.PastJudgements},
		{6, s.EntropyPool},
		{7, s.ValidatorState.QueuedValidators},
		{8, s.ValidatorState.CurrentValidators},
		{9, s.ValidatorState.ArchivedValidators},
		{10, s.CoreAssignments},
		{11, s.TimeslotIndex},
		{12, s.PrivilegedServices}, // TODO update when GP updates for this are released.
		{13, s.ActivityStatistics},
		{14, s.AccumulationQueue},
		{15, s.AccumulationHistory},
		{16, s.AccumulationOutputLog},
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

// C(255, s) ↦ a_c ⌢ E_8(a_b, a_g , a_m, a_o, a_f ) ⌢ E4(a_i, a_r , a_a, a_p)
func serializeServiceAccount(serviceId block.ServiceId, serviceAccount service.ServiceAccount, serializedState map[statekey.StateKey][]byte) error {
	// Serialize the service account itself.
	encodedServiceAccount := encodedServiceAccount{
		CodeHash:                       serviceAccount.CodeHash,
		Balance:                        serviceAccount.Balance,
		GasLimitForAccumulator:         serviceAccount.GasLimitForAccumulator,
		GasLimitOnTransfer:             serviceAccount.GasLimitOnTransfer,
		FootprintStorage:               serviceAccount.GetTotalNumberOfOctets(),
		GratisStorageOffset:            serviceAccount.GratisStorageOffset,
		FootprintItems:                 serviceAccount.GetTotalNumberOfItems(),
		CreationTimeslot:               serviceAccount.CreationTimeslot,
		MostRecentAccumulationTimeslot: serviceAccount.MostRecentAccumulationTimeslot,
		ParentService:                  serviceAccount.ParentService,
	}

	encodedServiceValue, err := jam.Marshal(encodedServiceAccount)
	if err != nil {
		return err
	}

	stateKey, err := statekey.NewService(serviceId)
	if err != nil {
		return err
	}
	serializedState[stateKey] = encodedServiceValue

	// Serialize the service's preimage lookups.
	if err := serializePreimageLookup(serviceId, serviceAccount.PreimageLookup, serializedState); err != nil {
		return err
	}

	// Serialize the service's storage and preimage meta keys. We can't tell
	// these apart in all cases, and we don't need to since they are already in
	// the serialized key value format.
	for sk, value := range serviceAccount.GetGlobalKVItems() {
		serializedState[sk] = value
	}

	return nil
}

type encodedServiceAccount struct {
	CodeHash crypto.Hash // a_c

	Balance                uint64 // a_b
	GasLimitForAccumulator uint64 // a_g
	GasLimitOnTransfer     uint64 // a_m
	FootprintStorage       uint64 // a_o
	GratisStorageOffset    uint64 // a_f

	FootprintItems                 uint32           // a_i
	CreationTimeslot               jamtime.Timeslot // a_r
	MostRecentAccumulationTimeslot jamtime.Timeslot // a_a
	ParentService                  block.ServiceId  // a_p
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

func CloneState(in state.State) (state.State, error) {
	serialized, err := SerializeState(in)
	if err != nil {
		return state.State{}, err
	}

	out, err := DeserializeState(serialized)
	if err != nil {
		return state.State{}, err
	}

	return out, nil
}
