package pebble

import (
	"github.com/cockroachdb/pebble"
	"github.com/eigerco/strawberry/pkg/db"
	"sync/atomic"
)

type Batch struct {
	batch *pebble.Batch
	done  atomic.Bool
}

func (p *KVStore) NewBatch() db.Batch {
	return &Batch{
		batch: p.db.NewBatch(),
	}
}

func (b *Batch) Put(key, value []byte) error {
	if b.done.Load() {
		return ErrBatchDone
	}
	return b.batch.Set(key, value, nil)
}

func (b *Batch) Delete(key []byte) error {
	if b.done.Load() {
		return ErrBatchDone
	}
	return b.batch.Delete(key, nil)
}

func (b *Batch) Commit() error {
	if b.done.Load() {
		return ErrBatchDone
	}
	if err := b.batch.Commit(pebble.Sync); err != nil {
		return err
	}
	b.done.Store(true)
	return nil
}

func (b *Batch) Close() error {
	if !b.done.CompareAndSwap(false, true) {
		return nil
	}
	return b.batch.Close()
}
