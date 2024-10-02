package state

import (
	"github.com/eigerco/strawberry/internal/block"
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/jamtime"
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
