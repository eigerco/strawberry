package kv_store

import (
	"github.com/cockroachdb/pebble"
	"sync"
)

type PebbleBatch struct {
	batch *pebble.Batch
	mu    sync.Mutex
}

func (p *PebbleStore) NewBatch() Batch {
	return &PebbleBatch{
		batch: p.db.NewBatch(),
	}
}

func (b *PebbleBatch) Put(key, value []byte) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.batch.Set(key, value, nil)
}

func (b *PebbleBatch) Delete(key []byte) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.batch.Delete(key, nil)
}

func (b *PebbleBatch) Commit() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.batch.Commit(pebble.Sync)
}

func (b *PebbleBatch) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.batch.Close()
}
