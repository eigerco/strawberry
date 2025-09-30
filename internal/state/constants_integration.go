//go:build tiny

package state

const (
	MaxTimeslotsForLookupAnchor             = 24   // (L) Maximum age for lookup-anchor blocks in work reports
	MaxRecentBlocks                         = 8    // (H) Maximum number of recent blocks to store
	MaxAuthorizersPerCore                   = 8    // (O) The maximum number of items in the authorizers pool.
	EntropyPoolSize                         = 4    // () Size of the entropy pool
	PendingAuthorizersQueueSize             = 80   // (Q) The maximum number of items in the authorizers queue.
	MaximumNumberOfEntriesAccumulationQueue = 1024 // (S) The maximum number of entries in the accumulation queue.

	MaximumSizeIsAuthorizedCode = 64_000 // (WA) The maximum size of is-authorized code in octets

	SignatureContextGuarantee = "jam_guarantee" // X_G ≡ $jam_guarantee (11.27 v0.6.2)
	SignatureContextAvailable = "jam_available" // X_A ≡ $jam_available (11.14 v0.6.2)
	SignatureContextValid     = "jam_valid"     // X_A ≡ $jam_valid (10.4 v0.6.2)
	SignatureContextInvalid   = "jam_invalid"   // X_A ≡ $jam_invalid (10.4 v0.6.2)
)
