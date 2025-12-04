package service

import (
	"fmt"
	"slices"

	"github.com/eigerco/strawberry/internal/block"
	"github.com/eigerco/strawberry/internal/common"
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/jamtime"
	"github.com/eigerco/strawberry/internal/safemath"
	"github.com/eigerco/strawberry/internal/state/serialization/statekey"
	"github.com/eigerco/strawberry/pkg/serialization/codec/jam"
)

const (
	BasicMinimumBalance              = 100 // (BS) The basic minimum balance which all services require.
	AdditionalMinimumBalancePerItem  = 10  // (BI) The additional minimum balance required per item of elective service state.
	AdditionalMinimumBalancePerOctet = 1   // (BL) The additional minimum balance required per octet of elective service state.
	TransferMemoSizeBytes            = 128 // (WT) Size of the transfer memo in bytes.
)

type ServiceState map[block.ServiceId]ServiceAccount

func (ss ServiceState) Clone() ServiceState {
	if ss == nil {
		return nil
	}

	cloned := make(ServiceState, len(ss))
	for k, v := range ss {
		cloned[k] = v.Clone()
	}

	return cloned
}

// ServiceAccount represents a service account in the JAM state
type ServiceAccount struct {
	PreimageLookup                 map[crypto.Hash][]byte // Dictionary of preimage lookups (p)
	GratisStorageOffset            uint64                 // Gratis storage offset (f ∈ N_B)
	CodeHash                       crypto.Hash            // Hash of the service code (c)
	Balance                        uint64                 // Balance of the service (b)
	GasLimitForAccumulator         uint64                 // Gas limit for accumulation (g)
	GasLimitOnTransfer             uint64                 // Gas limit for on_transfer (m)
	CreationTimeslot               jamtime.Timeslot       // The time slot at creation (r ∈ NT)
	MostRecentAccumulationTimeslot jamtime.Timeslot       // The time slot at the most recent accumulation (a ∈ NT)
	ParentService                  block.ServiceId        // The parent service (p ∈ NS)
	// globalKV stores all service storage (s) and preimage meta (l) entries keyed by statekey.StateKey
	// This unification simplifies serialization and total footprint calculation
	globalKV            map[statekey.StateKey][]byte
	totalNumberOfItems  uint32 // ai total number of items in storage, maintained incrementally
	totalNumberOfOctets uint64 // ao total number of octets/bytes in storage, maintained incrementally
}

func NewServiceAccount() ServiceAccount {
	return ServiceAccount{
		PreimageLookup: map[crypto.Hash][]byte{},
		globalKV:       map[statekey.StateKey][]byte{},
	}
}

// GetGlobalKVItems returns the global KV map.
func (sa *ServiceAccount) GetGlobalKVItems() map[statekey.StateKey][]byte {
	return sa.globalKV
}

// SetGlobalKVItems sets the global KV map, this should only be used when
// deserializing state for now.
func (sa *ServiceAccount) SetGlobalKVItems(globalKV map[statekey.StateKey][]byte) {
	sa.globalKV = globalKV
}

// GetStorage retrieves the preimage storage associated with the given key
func (sa *ServiceAccount) GetStorage(key statekey.StateKey) ([]byte, bool) {
	value, ok := sa.globalKV[key]
	return value, ok
}

// GetTotalNumberOfItems returns `ai` total number of items in storage
func (sa *ServiceAccount) GetTotalNumberOfItems() uint32 {
	return sa.totalNumberOfItems
}

// SetTotalNumberOfItems sets `ai` total number of items in storage. This should
// only be used when deserializing state for now.
func (sa *ServiceAccount) SetTotalNumberOfItems(n uint32) {
	sa.totalNumberOfItems = n
}

// GetTotalNumberOfOctets return `ao` total number of octets/bytes in storage
func (sa *ServiceAccount) GetTotalNumberOfOctets() uint64 {
	return sa.totalNumberOfOctets
}

// SetTotalNumberOfOctets sets `ao` total number of octets/bytes in storage.
// This should only be used when deserializing state for now.
func (sa *ServiceAccount) SetTotalNumberOfOctets(n uint64) {
	sa.totalNumberOfOctets = n
}

// InsertStorage adds a new storage entry and updates item and octet counters accordingly (9.8 v0.7.0)
func (sa *ServiceAccount) InsertStorage(key statekey.StateKey, originalKeySize uint64, value []byte) {
	if sa.globalKV == nil {
		sa.globalKV = make(map[statekey.StateKey][]byte)
	}

	if prevVal, ok := sa.GetStorage(key); !ok {
		sa.totalNumberOfItems += 1
		sa.totalNumberOfOctets += 34 + originalKeySize + uint64(len(value))
	} else {
		sa.totalNumberOfOctets -= uint64(len(prevVal))
		sa.totalNumberOfOctets += uint64(len(value))
	}

	sa.globalKV[key] = value
}

// DeleteStorage removes a storage entry and updates both the item and octet counters accordingly (9.8 v0.7.0)
func (sa *ServiceAccount) DeleteStorage(key statekey.StateKey, keyLen uint64, valueLen uint64) {
	if _, ok := sa.GetStorage(key); ok {
		delete(sa.globalKV, key)
		if sa.totalNumberOfItems >= 1 {
			sa.totalNumberOfItems -= 1
		}
		sizeToSubtract := 34 + keyLen + valueLen
		if sa.totalNumberOfOctets >= sizeToSubtract {
			sa.totalNumberOfOctets -= 34 + keyLen + valueLen
		}
	}
}

// GetPreimageMeta retrieves and unmarshals the preimage metadata (historical timeslots) associated with the given key
func (sa *ServiceAccount) GetPreimageMeta(key statekey.StateKey) (PreimageHistoricalTimeslots, bool) {
	value, ok := sa.globalKV[key]
	if !ok {
		return nil, false
	}

	var timeslots PreimageHistoricalTimeslots
	if err := jam.Unmarshal(value, &timeslots); err != nil {
		return nil, false
	}

	return timeslots, true
}

// InsertPreimageMeta adds a new preimage entry and updates the item and octet counters accordingly (9.8 v0.7.0)
// can return either a codec error or an ErrOverflow
func (sa *ServiceAccount) InsertPreimageMeta(key statekey.StateKey, length uint64, timeslots PreimageHistoricalTimeslots) error {
	data, err := jam.Marshal(timeslots)
	if err != nil {
		return err
	}
	if sa.globalKV == nil {
		sa.globalKV = make(map[statekey.StateKey][]byte)
	}

	if _, ok := sa.GetPreimageMeta(key); !ok {
		// Update footprint
		sa.totalNumberOfItems, ok = safemath.Add32(sa.totalNumberOfItems, 2)
		if !ok {
			return safemath.ErrOverflow
		}
		sa.totalNumberOfOctets, ok = safemath.Add64(sa.totalNumberOfOctets, 81)
		if !ok {
			return safemath.ErrOverflow
		}
		sa.totalNumberOfOctets, ok = safemath.Add64(sa.totalNumberOfOctets, length)
		if !ok {
			return safemath.ErrOverflow
		}
	}

	sa.globalKV[key] = data

	return nil
}

// UpdatePreimageMeta updates the value for an existing key without altering accounting fields (9.8 v0.7.0)
func (sa *ServiceAccount) UpdatePreimageMeta(key statekey.StateKey, newValue PreimageHistoricalTimeslots) error {
	if sa.globalKV == nil {
		return fmt.Errorf("cannot update preimage meta: globalKV map is nil")
	}
	if _, exists := sa.globalKV[key]; !exists {
		return fmt.Errorf("cannot update preimage meta: key does not exist")
	}

	newBytes, err := jam.Marshal(newValue)
	if err != nil {
		return err
	}

	sa.globalKV[key] = newBytes

	return nil
}

// DeletePreimageMeta removes a preimage entry and updates both the item and octet counters accordingly (9.8 v0.7.0)
func (sa *ServiceAccount) DeletePreimageMeta(key statekey.StateKey, length uint64) {
	if _, ok := sa.GetPreimageMeta(key); ok {
		delete(sa.globalKV, key)
		if sa.totalNumberOfItems >= 2 {
			sa.totalNumberOfItems -= 2
		}
		sizeToSubtract := 81 + length
		if sa.totalNumberOfOctets >= sizeToSubtract {
			sa.totalNumberOfOctets -= sizeToSubtract
		}
	}
}

type CodeWithMetadata struct {
	Metadata []byte // a_m
	Code     []byte // a_c
}

// EncodedCodeAndMetadata encoded code and metadata as per Equation (9.4 v0.6.3)
func (sa *ServiceAccount) EncodedCodeAndMetadata() []byte {
	if code, exists := sa.PreimageLookup[sa.CodeHash]; exists {
		return code
	}
	return nil
}

// ThresholdBalance (9.8 v0.7.0) ∀a ∈ V(δ): at
func (sa *ServiceAccount) ThresholdBalance() uint64 {
	ai := uint64(sa.totalNumberOfItems)
	ao := sa.totalNumberOfOctets

	// at ∈ NB ≡ max(0,BS + BI ⋅ ai + BL ⋅ ao − af )
	sum := BasicMinimumBalance +
		AdditionalMinimumBalancePerItem*ai +
		AdditionalMinimumBalancePerOctet*ao

	// avoid underflow
	if sum < sa.GratisStorageOffset {
		return 0
	}

	return sum - sa.GratisStorageOffset
}

// AddPreimage adds a preimage to the service account's preimage lookup and metadata
// (9.6 v0.7.0) ∀a ∈ A, (h ↦ d) ∈ ap ⇒ h = H(d) ∧ {h, |d|} ∈ K(al)
func (sa *ServiceAccount) AddPreimage(serviceID block.ServiceId, p []byte, currentTimeslot jamtime.Timeslot) error {
	h := crypto.HashData(p)
	k, err := statekey.NewPreimageMeta(serviceID, h, uint32(len(p)))
	if err != nil {
		return err
	}

	if _, exists := sa.PreimageLookup[h]; exists {
		metadata, exists := sa.GetPreimageMeta(k)
		if !exists {
			return nil
		}

		if len(metadata) < common.MaxHistoricalTimeslotsForPreimageMeta {
			metadata = append(metadata, currentTimeslot)
			err = sa.UpdatePreimageMeta(k, metadata)
			if err != nil {
				return err
			}
		}

		return nil
	}

	// Add new preimage
	sa.PreimageLookup[h] = p

	return sa.InsertPreimageMeta(k, uint64(len(p)), PreimageHistoricalTimeslots{currentTimeslot})
}

// LookupPreimage implements the historical lookup function (Λ) as defined in Equation (9.7 v0.5.4).
func (sa *ServiceAccount) LookupPreimage(serviceID block.ServiceId, t jamtime.Timeslot, h crypto.Hash) []byte {
	p, exists := sa.PreimageLookup[h]
	if !exists {
		return nil
	}

	key, err := statekey.NewPreimageMeta(serviceID, h, uint32(len(p)))
	if err != nil {
		return nil
	}

	metadata, exists := sa.GetPreimageMeta(key)

	if !exists {
		return nil
	}

	// Determine if the preimage was available at timeslot t using I(al[h, |p|], t)
	available := isPreimageAvailableAt(metadata, t)

	if available {
		return p
	}

	return nil
}

// Clone returns a deep copy of the service account
func (sa *ServiceAccount) Clone() ServiceAccount {
	cloned := *sa

	cloned.globalKV = cloneMapOfSlices(sa.globalKV)
	cloned.PreimageLookup = cloneMapOfSlices(sa.PreimageLookup)

	return cloned
}

// isPreimageAvailableAt determines availability based on historical timeslots
// ● h = []: The preimage is requested, but has not yet been supplied.
// ● h ∈ [h0]: The preimage is available and has been from time h0.
// ● h ∈ [h0, h1): The preimage was available from h0 until h1.
// ● h ∈ [h0, h1) ∨ [h2, ∞): The preimage was available from h0 until h1 and from h2 onwards.
func isPreimageAvailableAt(metadata PreimageHistoricalTimeslots, t jamtime.Timeslot) bool {
	switch len(metadata) {
	case 0:
		return false
	case 1:
		return metadata[0] <= t
	case 2:
		return metadata[0] <= t && t < metadata[1]
	case 3:
		return (metadata[0] <= t && t < metadata[1]) || (metadata[2] <= t)
	}

	// More than 3 timeslots are not allowed
	return false
}

type PrivilegedServices struct {
	ManagerServiceId         block.ServiceId                            // Manager service ID (M) - the service able to effect an alteration of PrivilegedServices from block to block. Also called Empower service.
	AssignedServiceIds       [common.TotalNumberOfCores]block.ServiceId // Assigned service ids (A) - the service indices capable of altering the pending authorizer queue φ, one for each core.
	DesignateServiceId       block.ServiceId                            // Designate service ID (V) - the service able to effect an alteration of the NextValidators in ValidatorState.
	CreateProtectedServiceId block.ServiceId                            // Create protected service ID - (R) the service able to create new service accounts with indices in the protected range.
	AmountOfGasPerServiceId  map[block.ServiceId]uint64                 // Amount of gas per service ID (Z) - small dictionary containing the indices of services which automatically accumulate in each block together with a basic amount of gas with which each accumulates.
}

type PreimageLength uint32
type PreImageMetaKey struct {
	Hash   crypto.Hash    // Hash of the preimage ()
	Length PreimageLength // Length (presupposed) of the preimage ()
}
type PreimageHistoricalTimeslots []jamtime.Timeslot // Metadata for preimages (l) - TODO: There is a MaxHistoricalTimeslotsForPreimageMeta.

type Memo [TransferMemoSizeBytes]byte

// DeferredTransfer X ≡ (s ∈ Ns, d ∈ Ns, a ∈ Nb, m ∈ B_WT, g ∈ Ng) (eq. 12.14 v0.7.1)
type DeferredTransfer struct {
	SenderServiceIndex   block.ServiceId // sender service index (s)
	ReceiverServiceIndex block.ServiceId // receiver service index (d)
	Balance              uint64          // balance value (a)
	Memo                 Memo            // memo (m)
	GasLimit             uint64          // gas limit (g)
}

// cloneMapOfSlices creates a deep copy of a map where values are slices.
// Similar to maps.Clone, but also clones the slice values.
func cloneMapOfSlices[K comparable, V ~[]E, E any](m map[K]V) map[K]V {
	if m == nil {
		return nil
	}

	clone := make(map[K]V, len(m))
	for k, v := range m {
		clone[k] = slices.Clone(v)
	}

	return clone
}
