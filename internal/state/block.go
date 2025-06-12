package state

import (
	"github.com/eigerco/strawberry/internal/crypto"
)

// β ∈ (βH , βB) equation 7.1
type RecentHistory struct {
	// βH , state information for the most recent blocks. Limited to H blocks, i.e. MaxRecentBlocks
	BlockHistory []BlockState
	// βB, a merkle mountain range of all accumulation results . Equation 7.3
	AccumulationOutputLog []*crypto.Hash
}

// BlockState represents the details of the most recent blocks.
// Equation 7.2
type BlockState struct {
	HeaderHash crypto.Hash // Hash of the block header (h)
	// Merkle commitment to the block's accumulation output log, ie, the super peak of the MMR (b)
	BeefyRoot crypto.Hash
	// State root (s)
	StateRoot crypto.Hash
	// Work-reports included on this block, a map of work package hash to segment-root (p)
	Reported map[crypto.Hash]crypto.Hash
}
