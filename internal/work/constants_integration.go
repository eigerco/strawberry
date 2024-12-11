//go:build integration

package common

const (
	MaxNumberOfEntries                  = 1 << 11
	NumberOfErasureCodecPiecesInSegment = 6
	SizeOfErasureCodecPiecesInOctets    = 684
	SizeOfSegment                       = NumberOfErasureCodecPiecesInSegment * SizeOfErasureCodecPiecesInOctets
	MaxSizeOfEncodedWorkPackage         = 12 * 1 << 20
	MaxAllocatedGasRefine               = 500_000_000
)
