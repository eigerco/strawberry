package work

import (
	"github.com/eigerco/strawberry/internal/block"
	"github.com/eigerco/strawberry/internal/crypto"
)

type ImportedSegment struct {
	Hash  crypto.Hash
	Index uint16
}

type Extrinsic struct {
	Hash   crypto.Hash
	Length uint32
}

// Item represents I (14.2 v0.5.4)
type Item struct {
	ServiceId          uint32            // s ∈ N_S
	CodeHash           crypto.Hash       // c ∈ H
	Payload            []byte            // y ∈ Y
	GasLimitRefine     uint64            // g ∈ N_G
	GasLimitAccumulate uint64            // a ∈ N_G
	ImportedSegments   []ImportedSegment // i ∈ ⟦{H ∪ (H⊞), N}⟧
	Extrinsics         []Extrinsic       // x ∈ ⟦(H, N)⟧
	ExportedSegments   uint16            // e ∈ N
}

func (w *Item) Size() uint64 {
	// S(w) = |w.y| + |w.i| * WG + Σ(h,l)∈w.x l
	total := uint64(len(w.Payload))                          // |w.y|
	total += uint64(len(w.ImportedSegments)) * SizeOfSegment // |w.i| * WG
	for _, bh := range w.Extrinsics {
		total += uint64(bh.Length)
	}
	return total
}

// ToWorkResult item-to-result function C (14.8 v0.5.4)
func (w *Item) ToWorkResult(o block.WorkResultOutputOrError) block.WorkResult {
	payloadHash := crypto.HashData(w.Payload)

	gasPrioritizationRatio := uint64(0)
	if w.GasLimitAccumulate > 0 {
		gasPrioritizationRatio = w.GasLimitRefine / w.GasLimitAccumulate
	}

	return block.WorkResult{
		ServiceId:              block.ServiceId(w.ServiceId),
		ServiceHashCode:        w.CodeHash,
		PayloadHash:            payloadHash,
		GasPrioritizationRatio: gasPrioritizationRatio,
		Output:                 o,
	}
}
