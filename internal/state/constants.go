package state

const (
	MaxTimeslotsForPreimage     = 14400 // (L) Maximum number of timeslots for preimage metadata
	MaxRecentBlocks             = 8     // (H) Maximum number of recent blocks to store
	MaxAuthorizersPerCore       = 8     // (O) The maximum number of items in the authorizers pool.
	EntropyPoolSize             = 4     // () Size of the entropy pool
	PendingAuthorizersQueueSize = 80    // (Q) The maximum number of items in the authorizers queue.

	SignatureContextGuarantee = "jam_guarantee" // X_G ≡ $jam_guarantee (11.27 v0.6.2)
	SignatureContextAvailable = "jam_available" // X_A ≡ $jam_available (11.14 v0.6.2)
	SignatureContextValid     = "jam_valid"     // X_A ≡ $jam_valid (10.4 v0.6.2)
	SignatureContextInvalid   = "jam_invalid"   // X_A ≡ $jam_invalid (10.4 v0.6.2)
)
