package store

import (
	"encoding/binary"
	"fmt"
	"log"
	"math"

	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/pkg/db"
	"github.com/eigerco/strawberry/pkg/serialization/codec/jam"
)

// NewShards creates a new availability store
func NewShards(db db.KVStore) *Shards {
	return &Shards{db: db}
}

// Shards responsible for storing the bundle and segments shards and justifications
type Shards struct {
	db db.KVStore
}

// PutAllShardsAndJustifications stores all segment shards, audit bundle shards and justification in one batch for an erasure root
// we assume that the number of shards is the same for bundleShard, segmentsShard and justifications, this should be checked before calling the method
func (a *Shards) PutAllShardsAndJustifications(erasureRoot crypto.Hash, bundleShards [][]byte, segmentsShards [][][]byte, justifications [][][]byte) error {
	batch := a.db.NewBatch()
	defer func() {
		if err := batch.Close(); err != nil {
			log.Printf("error closing store: %v", err)
		}
	}()

	// store all the items in a single batch
	for shardIndex := range bundleShards {
		var segmentsShard [][]byte
		if segmentsShards != nil {
			segmentsShard = segmentsShards[shardIndex]
		}
		if shardIndex > math.MaxUint16 {
			return fmt.Errorf("shard index out of bounds: %v", shardIndex)
		}
		if err := a.putShardsAndJustification(batch, erasureRoot, uint16(shardIndex), bundleShards[shardIndex], segmentsShard, justifications[shardIndex]); err != nil {
			return fmt.Errorf("unable to store shards and justifications: %v", err)
		}
	}
	return batch.Commit()
}

// PutShardsAndJustification stores segment shards, audit bundle shards and justification in one batch for an erasure root and shard index
func (a *Shards) PutShardsAndJustification(erasureRoot crypto.Hash, shardIndex uint16, bundleShard []byte, segmentsShard [][]byte, justification [][]byte) error {
	batch := a.db.NewBatch()
	defer func() {
		if err := batch.Close(); err != nil {
			log.Printf("error closing store: %v", err)
		}
	}()

	if err := a.putShardsAndJustification(batch, erasureRoot, shardIndex, bundleShard, segmentsShard, justification); err != nil {
		return err
	}

	return batch.Commit()
}

func (a *Shards) putShardsAndJustification(writer db.Writer, erasureRoot crypto.Hash, shardIndex uint16, bundleShard []byte, segmentsShard [][]byte, justification [][]byte) error {
	// encode and store bundle shards
	if err := writer.Put(makeAvailabilityKey(prefixAvailabilityAuditShard, erasureRoot, shardIndex), bundleShard); err != nil {
		return fmt.Errorf("unable to store audit bundle shard: %w", err)
	}

	// encode and store segments shards
	segmentsBytes, err := jam.Marshal(segmentsShard)
	if err != nil {
		return fmt.Errorf("unable to marshal segments shard: %w", err)
	}
	if err := writer.Put(makeAvailabilityKey(prefixAvailabilitySegmentsShard, erasureRoot, shardIndex), segmentsBytes); err != nil {
		return fmt.Errorf("unable to store segments shard: %w", err)
	}

	// encode and store justification
	justificationBytes, err := jam.Marshal(justification)
	if err != nil {
		return fmt.Errorf("unable to marshal justification: %w", err)
	}
	if err := writer.Put(makeAvailabilityKey(prefixAvailabilityJustification, erasureRoot, shardIndex), justificationBytes); err != nil {
		return fmt.Errorf("unable to store justification: %w", err)
	}
	return nil
}

// GetAuditShard gets an audit shard by erasure root and shard index
func (a *Shards) GetAuditShard(erasureRoot crypto.Hash, shardIndex uint16) ([]byte, error) {
	val, err := a.db.Get(makeAvailabilityKey(prefixAvailabilityAuditShard, erasureRoot, shardIndex))
	if err != nil {
		return nil, fmt.Errorf("unable to get audit bundle shard: %w", err)
	}

	return val, nil
}

// GetSegmentsShard gets a segment shard by erasure root and shard index
func (a *Shards) GetSegmentsShard(erasureRoot crypto.Hash, shardIndex uint16) ([][]byte, error) {
	val, err := a.db.Get(makeAvailabilityKey(prefixAvailabilitySegmentsShard, erasureRoot, shardIndex))
	if err != nil {
		return nil, fmt.Errorf("unable to store segments shard: %w", err)
	}

	segmentsShards := [][]byte{}
	if err := jam.Unmarshal(val, &segmentsShards); err != nil {
		return nil, fmt.Errorf("unable to unmarshal segments shard: %w", err)
	}
	return segmentsShards, nil
}

// GetJustification gets a justification by erasure root and shard index
func (a *Shards) GetJustification(erasureRoot crypto.Hash, shardIndex uint16) ([][]byte, error) {
	val, err := a.db.Get(makeAvailabilityKey(prefixAvailabilityJustification, erasureRoot, shardIndex))
	if err != nil {
		return nil, fmt.Errorf("unable to get justification: %w", err)
	}

	justification := [][]byte{}
	if err := jam.Unmarshal(val, &justification); err != nil {
		return nil, fmt.Errorf("unable to unmarshal justification: %w", err)
	}

	return justification, nil
}

// makeAvailabilityKey constructs a key for storing availability shards and justifications
// a key is the concatenation of prefix ++ Erasure-Root ++ Shard-Index
func makeAvailabilityKey(prefix byte, erasureRoot crypto.Hash, shardIndex uint16) []byte {
	key := make([]byte, len(erasureRoot)+3)
	key[0] = prefix
	copy(key[1:], erasureRoot[:])
	binary.LittleEndian.PutUint16(key[33:], shardIndex)
	return key
}
