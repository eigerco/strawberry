package service

import (
	"slices"

	"github.com/eigerco/strawberry/internal/block"
	"github.com/eigerco/strawberry/internal/common"
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/jamtime"
	"github.com/eigerco/strawberry/internal/state/serialization/statekey"
)

const (
	BasicMinimumBalance              = 100         // (BS) The basic minimum balance which all services require.
	AdditionalMinimumBalancePerItem  = 10          // (BI) The additional minimum balance required per item of elective service state.
	AdditionalMinimumBalancePerOctet = 1           // (BL) The additional minimum balance required per octet of elective service state.
	TransferMemoSizeBytes            = 128         // (WT) Size of the transfer memo in bytes.
	TotalGasAccumulation             = 341_000_000 // GT = 341,000,000: Total gas allocated across all cores for Accumulation
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
	// Storage uses a state key for it's key. We have to use the state key
	// representation as the key because serializing storage keys is lossy and
	// we'd like to be able to deserialize the storage dictionary later. Host
	// calls are called by PVM code code with the original storage key. The key
	// we end up using is merely an implementation detail. As long as we can
	// store and retrieve the key we are fine, we don't need to know the
	// original key here.
	Storage                map[statekey.StateKey][]byte                    // Dictionary of key-value pairs for storage (s)
	PreimageLookup         map[crypto.Hash][]byte                          // Dictionary of preimage lookups (p)
	PreimageMeta           map[PreImageMetaKey]PreimageHistoricalTimeslots // Metadata for preimageLookup (l) Graypaper 0.6.3 - TODO: There is a MaxTimeslotsForPreimage.
	CodeHash               crypto.Hash                                     // Hash of the service code (c)
	Balance                uint64                                          // Balance of the service (b)
	GasLimitForAccumulator uint64                                          // Gas limit for accumulation (g)
	GasLimitOnTransfer     uint64                                          // Gas limit for on_transfer (m)
}

type CodeWithMetadata struct {
	Metadata []byte // a_m
	Code     []byte // a_c
}

// EncodedCodeAndMetadata encoded code and metadata as per Equation (9.4 v0.6.3)
func (sa ServiceAccount) EncodedCodeAndMetadata() []byte {
	if code, exists := sa.PreimageLookup[sa.CodeHash]; exists {
		return code
	}
	return nil
}

// TotalItems (9.8 v0.6.5) ∀a ∈ V(δ): ai
func (sa ServiceAccount) TotalItems() uint32 {
	totalPreimages := len(sa.PreimageMeta)
	totalStorageItems := len(sa.Storage)
	// 2 ⋅ ∣ al ∣ + ∣ as ∣
	ai := 2*totalPreimages + totalStorageItems

	return uint32(ai)
}

// TotalStorageSize (9.8 v0.6.5) ∀a ∈ V(δ): ao
func (sa ServiceAccount) TotalStorageSize() uint64 {
	var ao uint64 = 0

	// PreimageLookup sizes ∑(h,z)∈K(al) 81 + z
	for k := range sa.PreimageMeta {
		ao += 81 + uint64(k.Length)
	}

	// Storage sizes ∑ x∈V(as) 32 + ∣x∣
	for _, x := range sa.Storage {
		xSize := uint64(len(x))
		ao += 32 + xSize
	}

	return ao
}

// ThresholdBalance (9.8 v0.6.5) ∀a ∈ V(δ): at
func (sa ServiceAccount) ThresholdBalance() uint64 {
	ai := uint64(sa.TotalItems())
	ao := sa.TotalStorageSize()

	return BasicMinimumBalance + AdditionalMinimumBalancePerItem*ai + AdditionalMinimumBalancePerOctet*ao
}

// AddPreimage adds a preimage to the service account's preimage lookup and metadata
// (9.6 v0.5.0) ∀a ∈ A, (h ↦ p) ∈ ap ⇒ h = H(p) ∧ {h, |p|} ∈ K(al)
func (sa ServiceAccount) AddPreimage(p []byte, currentTimeslot jamtime.Timeslot) error {
	h := crypto.HashData(p)
	if _, exists := sa.PreimageLookup[h]; exists {
		metaKey := PreImageMetaKey{Hash: h, Length: PreimageLength(len(p))}
		metadata, exists := sa.PreimageMeta[metaKey]
		if !exists {
			return nil
		}

		if len(metadata) < common.MaxHistoricalTimeslotsForPreimageMeta {
			sa.PreimageMeta[metaKey] = append(metadata, currentTimeslot)
		}

		return nil
	}

	// Add new preimage
	sa.PreimageLookup[h] = p

	// Initialize metadata
	metaKey := PreImageMetaKey{Hash: h, Length: PreimageLength(len(p))}
	sa.PreimageMeta[metaKey] = PreimageHistoricalTimeslots{currentTimeslot}

	return nil
}

// LookupPreimage implements the historical lookup function (Λ) as defined in Equation (9.7 v0.5.4).
func (sa ServiceAccount) LookupPreimage(t jamtime.Timeslot, h crypto.Hash) []byte {
	p, exists := sa.PreimageLookup[h]
	if !exists {
		return nil
	}

	metaKey := PreImageMetaKey{Hash: h, Length: PreimageLength(len(p))}
	metadata, exists := sa.PreimageMeta[metaKey]
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
func (sa ServiceAccount) Clone() ServiceAccount {
	cloned := sa

	cloned.Storage = cloneMapOfSlices(sa.Storage)
	cloned.PreimageLookup = cloneMapOfSlices(sa.PreimageLookup)
	cloned.PreimageMeta = cloneMapOfSlices(sa.PreimageMeta)

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
	ManagerServiceId        block.ServiceId            // Manager service ID (m) - the service able to effect an alteration of PrivilegedServices from block to block. Also called Empower service.
	AssignServiceId         block.ServiceId            // Assign service ID (a) - the service able to effect an alteration of the PendingAuthorizersQueues.
	DesignateServiceId      block.ServiceId            // Designate service ID (v) - the service able to effect an alteration of the NextValidators in ValidatorState.
	AmountOfGasPerServiceId map[block.ServiceId]uint64 // Amount of gas per service ID (g) - small dictionary containing the indices of services which automatically accumulate in each block together with a basic amount of gas with which each accumulates.
}

type PreimageLength uint32
type PreImageMetaKey struct {
	Hash   crypto.Hash    // Hash of the preimage ()
	Length PreimageLength // Length (presupposed) of the preimage ()
}
type PreimageHistoricalTimeslots []jamtime.Timeslot // Metadata for preimages (l) - TODO: There is a MaxHistoricalTimeslotsForPreimageMeta.

type Memo [TransferMemoSizeBytes]byte

// DeferredTransfer Equation (12.14 v0.5.0): T ≡ (s ∈ Ns, d ∈ Ns, a ∈ Nb, m ∈ Ym, g ∈ Ng)
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
