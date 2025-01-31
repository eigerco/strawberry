package work

const (
	MaxSizeServiceCode          = 4000000 // WC = 4000000: The maximum size of service code in octets.
	MaxNumberOfEntries          = 1 << 11 // WM = 2^11: The maximum number of entries in a work-package manifest.
	SegmentsPerPage             = 64
	MaxSizeOfEncodedWorkPackage = 12 * 1 << 20 // WB = 12*2^20 = 12MB: The maximum size of an encoded work-package together with its extrinsic data and import implications, in octets.
	MaxAllocatedGasRefine       = 500_000_000  // GR = 500, 000, 000: The gas allocated to invoke a work-package’s Refine logic.
)
