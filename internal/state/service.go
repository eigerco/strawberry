package state

import (
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/time"
)

type ServiceId [32]byte
type ServiceState map[ServiceId]ServiceAccount

// ServiceAccount represents a service account in the JAM state
type ServiceAccount struct {
	Storage                map[crypto.Hash][]byte                          // Dictionary of key-value pairs for storage (s)
	Preimages              map[crypto.Hash][]byte                          // Dictionary of preimage lookups (p)
	PreimagesMeta          map[PreImageMetaKey]PreimageHistoricalTimeslots // Metadata for preimages (l) - TODO: There is a MaxTimeslotsForPreimage.
	CodeHash               crypto.Hash                                     // Hash of the service code (c)
	Balance                uint64                                          // Balance of the service (b)
	GasLimitForAccumulator uint64                                          // Gas limit for accumulation (g)
	GasLimitOnTransfer     uint64                                          // Gas limit for on_transfer (m)
}

type PrivilegedServices struct {
	ManagerServiceId   ServiceId // Manager service ID (m) - the service able to effect an alteration of PrivilegedServices from block to block. Also called Empower service.
	AssignServiceId    ServiceId // Assign service ID (a) - the service able to effect an alteration of the PendingAuthorizersQueues.
	DesignateServiceId ServiceId // Designate service ID (v) - the service able to effect an alteration of the NextValidators in ValidatorState.
}

type PreimageLength uint32
type PreImageMetaKey struct {
	Hash   crypto.Hash    // Hash of the preimage ()
	Length PreimageLength // Length (presupposed) of the preimage ()
}
type PreimageHistoricalTimeslots []time.Timeslot // Metadata for preimages (l) - TODO: There is a MaxHistoricalTimeslotsForPreimageMeta.