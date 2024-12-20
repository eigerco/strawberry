package state

import (
	"github.com/eigerco/strawberry/internal/crypto"
)

// BlockState represents the details of the most recent blocks. (v0.4.5)
type BlockState struct {
	HeaderHash            crypto.Hash                 // Hash of the block header (h)
	StateRoot             crypto.Hash                 // State root (b)
	AccumulationResultMMR []*crypto.Hash              // Accumulation-result MMR (s)
	WorkReportHashes      map[crypto.Hash]crypto.Hash // Hashes of work-reports (p)
}
