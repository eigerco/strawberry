package work

import (
	"io"

	"github.com/eigerco/strawberry/internal/block"
	"github.com/eigerco/strawberry/internal/constants"
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/pkg/serialization/codec/jam"
)

// Segment (G)
type Segment [constants.SizeOfSegment]byte

// UnmarshalJAM implements the JAM codec Unmarshaler interface.
func (s *Segment) UnmarshalJAM(r io.Reader) error {
	_, err := io.ReadFull(r, s[:])
	return err
}

type ImportedSegment struct {
	Hash  crypto.Hash
	Index uint16
}

// UnmarshalJAM implements the JAM codec Unmarshaler interface.
func (is *ImportedSegment) UnmarshalJAM(r io.Reader) error {
	if _, err := io.ReadFull(r, is.Hash[:]); err != nil {
		return err
	}
	buf := make([]byte, 2)
	if _, err := io.ReadFull(r, buf); err != nil {
		return err
	}
	is.Index = jam.DecodeUint16(buf)
	return nil
}

type Extrinsic struct {
	Hash   crypto.Hash
	Length uint32
}

// UnmarshalJAM implements the JAM codec Unmarshaler interface.
func (e *Extrinsic) UnmarshalJAM(r io.Reader) error {
	if _, err := io.ReadFull(r, e.Hash[:]); err != nil {
		return err
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(r, buf); err != nil {
		return err
	}
	e.Length = jam.DecodeUint32(buf)
	return nil
}

// Item represents I (14.2 v0.5.4)
// EE4(ws), wc, E8(wg ), E8(wa), E2(we), ↕wy, Õ × ÖI#(wi), ↕[(h, E4(i)) S (h, i) <− wx]
type Item struct {
	ServiceId          block.ServiceId   // s ∈ N_S
	CodeHash           crypto.Hash       // h ∈ H
	GasLimitRefine     uint64            // g ∈ N_G
	GasLimitAccumulate uint64            // a ∈ N_G
	ExportedSegments   uint16            // e ∈ N
	Payload            []byte            // y ∈ B
	ImportedSegments   []ImportedSegment // i ∈ ⟦{H ∪ (H⊞), N}⟧
	Extrinsics         []Extrinsic       // x ∈ ⟦(H, N)⟧
}

func (w *Item) Size() uint64 {
	// S(w) = |w.y| + |w.i| * WG + Σ(h,l)∈w.x l
	total := uint64(len(w.Payload))                                    // |w.y|
	total += uint64(len(w.ImportedSegments)) * constants.SizeOfSegment // |w.i| * WG
	for _, bh := range w.Extrinsics {
		total += uint64(bh.Length)
	}
	return total
}

// ToWorkResult item-to-result function C (14.8 v0.5.4)
func (w *Item) ToWorkResult(output block.WorkResultOutputOrError, gasUsed uint64) block.WorkDigest {
	payloadHash := crypto.HashData(w.Payload)

	gasPrioritizationRatio := uint64(0)
	if w.GasLimitAccumulate > 0 {
		gasPrioritizationRatio = w.GasLimitRefine / w.GasLimitAccumulate
	}

	extrinsicSize := uint32(0)
	for _, e := range w.Extrinsics {
		extrinsicSize += e.Length
	}
	return block.WorkDigest{
		ServiceId:             w.ServiceId,
		ServiceHashCode:       w.CodeHash,
		PayloadHash:           payloadHash,
		GasLimit:              gasPrioritizationRatio,
		Output:                output,
		GasUsed:               gasUsed,
		SegmentsImportedCount: uint16(len(w.ImportedSegments)),
		ExtrinsicCount:        uint16(len(w.Extrinsics)),
		ExtrinsicSize:         extrinsicSize,
		SegmentsExportedCount: w.ExportedSegments,
	}
}
