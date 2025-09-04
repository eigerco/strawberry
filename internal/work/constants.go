package work

const (
	MaxSizeServiceCode          = 4_000_000 // WC = 4,000,000: The maximum size of service code in octets.
	MaxNumberOfImports          = 3_072     // WM = 3,072: The maximum number of imports in a work-package
	MaxNumberOfExports                      // WX =  3,072: The maximum number of exports in a work-package
	MaxNumberOfItems            = 16        // I = 16: The maximum amount of work items in a package.
	MaxNumberOfDependencyItems  = 8         //J = 8 : The maximum sum of dependency items in a work-report
	MaxNumberOfExtrinsics       = 128       // T = 128: The maximum number of extrinsics in a work-package.
	SegmentsPerPage             = 64
	MaxSizeOfEncodedWorkPackage = 12 * 1 << 20 // WB = 12*2^20 = 12MB: The maximum size of an encoded work-package together with its extrinsic data and import implications, in octets.
)
