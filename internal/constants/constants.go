package constants

// Constants that are the same for all chain configurations

const (
	// State constants
	MaxRecentBlocks                         = 8      // (H) Maximum number of recent blocks to store
	MaxAuthorizersPerCore                   = 8      // (O) The maximum number of items in the authorizers pool.
	EntropyPoolSize                         = 4      // Size of the entropy pool
	PendingAuthorizersQueueSize             = 80     // (Q) The maximum number of items in the authorizers queue.
	MaximumNumberOfEntriesAccumulationQueue = 1024   // (S) The maximum number of entries in the accumulation queue.
	MaximumSizeIsAuthorizedCode             = 64_000 // (WA) The maximum size of is-authorized code in octets

	SignatureContextGuarantee = "jam_guarantee" // X_G ≡ $jam_guarantee (11.27 v0.6.2)
	SignatureContextAvailable = "jam_available" // X_A ≡ $jam_available (11.14 v0.6.2)
	SignatureContextValid     = "jam_valid"     // X_V ≡ $jam_valid (10.4 v0.6.2)
	SignatureContextInvalid   = "jam_invalid"   // X_I ≡ $jam_invalid (10.4 v0.6.2)

	// Common constants
	SlotPeriodInSeconds                   = 6          // P = 6: The slot period, in seconds
	WorkReportTimeoutPeriod               = 5          // U = 5: The period in timeslots after which reported but unavailable work may be replaced.
	MaxHistoricalTimeslotsForPreimageMeta = 3          // Maximum number of historical timeslots for preimage metadata
	MaxWorkPackageSize                    = 13_791_360 // WB = 13,791,360 (~13.16MB): The maximum size of work-package data in octets.
	MaxAllocatedGasAccumulation           = 10_000_000 // GA: The gas allocated to invoke a work-report's Accumulation logic.
	MaxAllocatedGasIsAuthorized           = 50_000_000 // GI: The gas allocated to invoke a work-package's Is-Authorized logic.
	WorkReportMaxSumOfDependencies        = 8          // (J) The maximum sum of dependency items in a work-report.
	MaxWorkPackageSizeBytes               = 48 * 1024  // (WR) Maximum size of a serialized work-package in bytes
	MaxNrImportsExports                   = 3072       // WM = 3072: The maximum number of imports and exports in a work-package.

	// Work package constants
	MaxSizeServiceCode         = 4_000_000 // WC = 4,000,000: The maximum size of service code in octets.
	MaxNumberOfImports         = 3_072     // WM = 3,072: The maximum number of imports in a work-package
	MaxNumberOfExports         = 3_072     // WX = 3,072: The maximum number of exports in a work-package
	MaxNumberOfItems           = 16        // I = 16: The maximum amount of work items in a package.
	MaxNumberOfDependencyItems = 8         // J = 8: The maximum sum of dependency items in a work-report
	MaxNumberOfExtrinsics      = 128       // T = 128: The maximum number of extrinsics in a work-package.
	SegmentsPerPage            = 64        // Number of segments per page

	// Derived constants
	AvailabilityThreshold          = (2 * NumberOfValidators) / 3                                 // Calculate the availability threshold (2/3 V)
	ValidatorsSuperMajority uint16 = (2 * NumberOfValidators / 3) + 1                             // 2/3V + 1
	SizeOfSegment                  = NumberOfErasureCodecPiecesInSegment * ErasureCodingChunkSize // WG = WP*WE: The size of a segment in octets.
)
