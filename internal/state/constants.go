package state

const (
	MaxTimeslotsForPreimage     = 14400 // (L) Maximum number of timeslots for preimage metadata
	MaxRecentBlocks             = 8     // (H) Maximum number of recent blocks to store
	MaxAuthorizersPerCore       = 8     // (O) The maximum number of items in the authorizers pool.
	EntropyPoolSize             = 4     // () Size of the entropy pool
	PendingAuthorizersQueueSize = 80    // (Q) The maximum number of items in the authorizers queue.
)
