package store

import (
	"encoding/binary"
	"fmt"
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/pkg/db"
	"github.com/eigerco/strawberry/pkg/serialization/codec/jam"
)

func NewAvailability(db db.KVStore) *Availability {
	return &Availability{db: db}
}

type Availability struct {
	db db.KVStore
}

func (a *Availability) PutShardsAndJustification(erasureRoot crypto.Hash, shardIndex uint16, bundleShard []byte, segmentsShard [][]byte, justification [][]byte) error {
	batch := a.db.NewBatch()
	defer batch.Close()

	if err := batch.Put(makeAvailabilityKey(prefixAvailabilityAuditShard, erasureRoot, shardIndex), bundleShard); err != nil {
		return fmt.Errorf("unable to store audit bundle shard: %w", err)
	}
	segmentsBytes, err := jam.Marshal(segmentsShard)
	if err != nil {
		return fmt.Errorf("unable to marshal segments shard: %w", err)
	}
	if err := batch.Put(makeAvailabilityKey(prefixAvailabilitySegmentsShard, erasureRoot, shardIndex), segmentsBytes); err != nil {
		return fmt.Errorf("unable to store segments shard: %w", err)
	}
	justificationBytes, err := jam.Marshal(justification)
	if err != nil {
		return fmt.Errorf("unable to marshal justification: %w", err)
	}
	if err := batch.Put(makeAvailabilityKey(prefixAvailabilityJustification, erasureRoot, shardIndex), justificationBytes); err != nil {
		return fmt.Errorf("unable to store justification: %w", err)
	}

	return batch.Commit()
}

func (a *Availability) GetAuditShard(erasureRoot crypto.Hash, shardIndex uint16) ([]byte, error) {
	val, err := a.db.Get(makeAvailabilityKey(prefixAvailabilityAuditShard, erasureRoot, shardIndex))
	if err != nil {
		return nil, fmt.Errorf("unable to get audit bundle shard: %w", err)
	}

	return val, nil
}

func (a *Availability) GetSegmentsShard(erasureRoot crypto.Hash, shardIndex uint16) ([][]byte, error) {
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

func (a *Availability) GetJustification(erasureRoot crypto.Hash, shardIndex uint16) ([][]byte, error) {
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
