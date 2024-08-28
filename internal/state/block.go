package state

import "github.com/eigerco/strawberry/internal/crypto"

// BlockState represents the details of the most recent blocks.
type BlockState struct {
	HeaderHash            crypto.Hash                     // Hash of the block header (h)
	StateRoot             []crypto.Hash                   // State root (b)
	AccumulationResultMMR crypto.Hash                     // Accumulation-result MMR (s)
	WorkReportHashes      [TotalNumberOfCores]crypto.Hash // Hashes of work-reports (p)
}
