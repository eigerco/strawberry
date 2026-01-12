package results

import (
	"fmt"

	"github.com/eigerco/strawberry/internal/constants"
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/erasurecoding"
	"github.com/eigerco/strawberry/internal/merkle/binary_tree"
	"github.com/eigerco/strawberry/internal/work"
	"github.com/eigerco/strawberry/pkg/serialization/codec/jam"
)

type Shards struct {
	Bundle                    [][]byte
	Segments                  [][][]byte // in case no segments are present this could be nil
	BundleHashAndSegmentsRoot [][]byte
}

// ShardBundleAndSegments shards the auditable work-package and segments, computes the hash for each auditable work-package shard and
// the merkle root for each bundle of segment shards and joins them together
// returns the auditable work-package shards, each segment shards and the work-package bundle shard hash, segment shard root pairs
// implements parts of eq. 14.16
func ShardBundleAndSegments(auditableBlob []byte, segments []work.Segment) (*Shards, error) {
	// H#(C⌈|b|/WE⌉(PWE(b)))
	padded := work.ZeroPadding(auditableBlob, constants.ErasureCodingChunkSize)
	auditableShards, err := erasurecoding.Encode(padded)
	if err != nil {
		return nil, err
	}

	// M#_B(T C#_6 (s ⌢ P(s)))
	pagedProofs, err := ComputePagedProofs(segments)
	if err != nil {
		return nil, fmt.Errorf("failed to compute paged proofs: %w", err)
	}

	segmentsWithProofs := append(segments, pagedProofs...)

	var shardsForSegments [][][]byte
	if len(segmentsWithProofs) > 0 {
		shardsForSegments = make([][][]byte, constants.NumberOfValidators)

		for _, segmentOrProof := range segmentsWithProofs {
			segmentOrProofShards, err := erasurecoding.Encode(segmentOrProof[:])
			if err != nil {
				return nil, fmt.Errorf("failed to erasure code segment or proof: %w", err)
			}
			for shardIndex, shard := range segmentOrProofShards {
				shardsForSegments[shardIndex] = append(shardsForSegments[shardIndex], shard)
			}
		}
	}

	auditableHashSegmentRootPairs := make([][]byte, constants.NumberOfValidators)
	for i := 0; i < constants.NumberOfValidators; i++ {
		auditShardHash := crypto.HashData(auditableShards[i])
		auditableHashSegmentRootPairs[i] = auditShardHash[:]
		if len(shardsForSegments) > 0 {
			segmentsShardsRoot := binary_tree.ComputeWellBalancedRoot(shardsForSegments[i], crypto.HashData)
			auditableHashSegmentRootPairs[i] = append(auditableHashSegmentRootPairs[i], segmentsShardsRoot[:]...)
		}
	}
	return &Shards{
		Bundle:                    auditableShards,
		Segments:                  shardsForSegments,
		BundleHashAndSegmentsRoot: auditableHashSegmentRootPairs,
	}, nil
}

// ComputePagedProofs P(s) → [E(J₆(s,i), L₆(s,i))₍l₎ | i ∈ ℕ₍⌈|s|/64⌉₎] (14.10 v0.5.4)
func ComputePagedProofs(segments []work.Segment) ([]work.Segment, error) {
	if len(segments) == 0 {
		return nil, nil
	}
	blobs := make([][]byte, len(segments))
	for i, seg := range segments {
		blobs[i] = seg[:]
	}
	numPages := (len(segments) + constants.SegmentsPerPage - 1) / constants.SegmentsPerPage
	pagedProofs := make([]work.Segment, numPages)
	for pageIndex := 0; pageIndex < numPages; pageIndex++ {
		// Get leaf hashes and proof for page
		leafHashes := binary_tree.GetLeafPage(blobs, pageIndex, constants.NumberOfErasureCodecPiecesInSegment, crypto.HashData)
		proof := binary_tree.GeneratePageProof(blobs, pageIndex, constants.NumberOfErasureCodecPiecesInSegment, crypto.HashData)

		// Encode leaves and proof
		marshalledLeaves, err := jam.Marshal(leafHashes)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal leaf hashes: %w", err)
		}
		marshalledProof, err := jam.Marshal(proof)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal proof: %w", err)
		}
		combined := append(marshalledLeaves, marshalledProof...)
		padded := work.ZeroPadding(combined, constants.SizeOfSegment)
		copy(pagedProofs[pageIndex][:], padded)
	}
	return pagedProofs, nil
}

func segmentsToByteSlices(segs []work.Segment) [][]byte {
	out := make([][]byte, len(segs))
	for i := range segs {
		out[i] = segs[i][:]
	}
	return out
}
