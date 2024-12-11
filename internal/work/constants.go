package work

const (
	MaxNumberOfEntries                  = 1 << 11                                                                // WM = 2^11: The maximum number of entries in a work-package manifest.
	NumberOfErasureCodecPiecesInSegment = 6                                                                      // WP = 6: The number of erasure-coded pieces in a segment.
	SizeOfErasureCodecPiecesInOctets    = 684                                                                    // WE = 684: The basic size of erasure-coded pieces in octets.
	SizeOfSegment                       = NumberOfErasureCodecPiecesInSegment * SizeOfErasureCodecPiecesInOctets // WG = WP*WE = 4104: The size of a segment in octets.
	MaxSizeOfEncodedWorkPackage         = 12 * 1 << 20                                                           // WB = 12*2^20 = 12MB: The maximum size of an encoded work-package together with its extrinsic data and import implications, in octets.
	MaxAllocatedGasRefine               = 500_000_000                                                            // GR = 500, 000, 000: The gas allocated to invoke a work-package’s Refine logic.
)
