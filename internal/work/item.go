package work

import (
	"github.com/eigerco/strawberry/internal/block"
	"github.com/eigerco/strawberry/internal/crypto"
)

// SegmentReferenceType differentiates between a direct segment-root hash (H) and a work-package hash (H⊞)
type SegmentReferenceType uint8

const (
	SegmentReferenceRootHash        SegmentReferenceType = iota // H
	SegmentReferenceWorkPackageHash                             // H⊞
)

type ImportedSegment struct {
	RefType SegmentReferenceType
	Hash    crypto.Hash
	Index   uint32
}

type BlobHashLengthPair struct {
	Hash   crypto.Hash
	Length uint32
}

// Item represents I (14.2 v0.5.2)
type Item struct {
	ServiceId          uint32               // s ∈ N_S
	CodeHash           crypto.Hash          // c ∈ H
	Payload            []byte               // y ∈ Y
	GasLimitRefine     uint64               // g ∈ N_G
	GasLimitAccumulate uint64               // a ∈ N_G
	ExportedSegments   uint                 // e ∈ N
	ImportedSegments   []ImportedSegment    // i ∈ ⟦{H ∪ (H⊞), N}⟧
	BlobHashLengths    []BlobHashLengthPair // x ∈ ⟦(H, N)⟧
}

func (w *Item) Size() uint64 {
	// S(w) = |w.y| + |w.i| * WG + Σ(h,l)∈w.x l
	total := uint64(len(w.Payload))                          // |w.y|
	total += uint64(len(w.ImportedSegments)) * SizeOfSegment // |w.i| * WG
	for _, bh := range w.BlobHashLengths {
		total += uint64(bh.Length)
	}
	return total
}

// ToWorkResult item-to-result function C (14.8 v0.5.2)
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
