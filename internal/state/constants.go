package state

const (
	MaxTimeslotsForPreimage               = 14400     // (L) Maximum number of timeslots for preimage metadata
	MaxHistoricalTimeslotsForPreimageMeta = 3         // () Maximum number of historical timeslots for preimage metadata
	TotalNumberOfCores                    = 341       // (C) Total number of cores in the system
	MaxRecentBlocks                       = 8         // (H) Maximum number of recent blocks to store
	MaxAuthorizersPerCore                 = 8         // (O) The maximum number of items in the authorizers pool.
	MinWorkPackageResultsSize             = 1         // () The minimum amount of work items in a package.
	MaxWorkPackageResultsSize             = 100       // (I) The maximum amount of work items in a package.
	MaxWorkPackageSizeBytes               = 96 * 1024 // (WR) Maximum size of a serialized work-package in bytes
	EntropyPoolSize                       = 4         // () Size of the entropy pool
	PendingAuthorizersQueueSize           = 80        // (Q) The maximum number of items in the authorizers queue.
)
