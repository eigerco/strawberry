package service

import (
	"github.com/eigerco/strawberry/internal/block"
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/jamtime"
)

const (
	BasicMinimumBalance                   = 100       // (BS) The basic minimum balance which all services require.
	AdditionalMinimumBalancePerItem       = 10        // (BI) The additional minimum balance required per item of elective service state.
	AdditionalMinimumBalancePerOctet      = 1         // (BL) The additional minimum balance required per octet of elective service state.
	TransferMemoSizeBytes                 = 128       // (M) Size of the transfer memo in bytes.
)


type ServiceState map[block.ServiceId]ServiceAccount

// ServiceAccount represents a service account in the JAM state
type ServiceAccount struct {
	Storage                map[crypto.Hash][]byte                          // Dictionary of key-value pairs for storage (s)
	PreimageLookup         map[crypto.Hash][]byte                          // Dictionary of preimage lookups (p)
	PreimageMeta           map[PreImageMetaKey]PreimageHistoricalTimeslots // Metadata for preimageLookup (l) - TODO: There is a MaxTimeslotsForPreimage.
	CodeHash               crypto.Hash                                     // Hash of the service code (c)
	Balance                uint64                                          // Balance of the service (b)
	GasLimitForAccumulator uint64                                          // Gas limit for accumulation (g)
	GasLimitOnTransfer     uint64                                          // Gas limit for on_transfer (m)
}

// TotalItems (94) ∀a ∈ V(δ): ai
func (sa *ServiceAccount) TotalItems() uint32 {
	totalPreimages := len(sa.PreimageLookup)
	totalStorageItems := len(sa.Storage)
	ai := 2*totalPreimages + totalStorageItems

	return uint32(ai)
}

// TotalStorageSize (94) ∀a ∈ V(δ): al
func (sa *ServiceAccount) TotalStorageSize() uint64 {
	var al uint64 = 0

	// PreimageLookup sizes
	for _, z := range sa.PreimageLookup {
		zSize := uint64(len(z))
		al += 81 + zSize
	}

	// Storage sizes
	for _, x := range sa.Storage {
		xSize := uint64(len(x))
		al += 32 + xSize
	}

	return al
}

// ThresholdBalance (94) ∀a ∈ V(δ): at
func (sa *ServiceAccount) ThresholdBalance() uint64 {
	ai := uint64(sa.TotalItems())
	al := sa.TotalStorageSize()

	return BasicMinimumBalance + AdditionalMinimumBalancePerItem*ai + AdditionalMinimumBalancePerOctet*al
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

// DeferredTransfer Equation 161: T ≡ (s ∈ Ns, d ∈ Ns, a ∈ Nb, m ∈ Ym, g ∈ Ng)
type DeferredTransfer struct {
	SenderServiceIndex   block.ServiceId // sender service index (s)
	ReceiverServiceIndex block.ServiceId // receiver service index (d)
	Balance              uint64          // balance value (a)
	Memo                 Memo            // memo (m)
	GasLimit             uint64          // gas limit (g)
}