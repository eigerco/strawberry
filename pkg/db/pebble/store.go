package pebble

import (
	"errors"
	"fmt"
	"github.com/cockroachdb/pebble"
	"github.com/cockroachdb/pebble/vfs"
	"sync/atomic"
)

type KVStore struct {
	db     *pebble.DB
	closed atomic.Bool
}

// NewKVStore initializes a new in-memory key-value store using Pebble.
func NewKVStore() (*KVStore, error) {
	opts := &pebble.Options{
		FS:                          vfs.NewMem(), // Use in-memory filesystem
		Cache:                       pebble.NewCache(64 * 1024 * 1024),
		MemTableSize:                32 * 1024 * 1024,
		MemTableStopWritesThreshold: 4,
	}

	db, err := pebble.Open("", opts) // Empty string for path when using in-memory FS
	if err != nil {
		return nil, err
	}

	return &KVStore{db: db}, nil
}

func (p *KVStore) Get(key []byte) ([]byte, error) {
	if p.closed.Load() {
		return nil, ErrClosed
	}

	value, closer, err := p.db.Get(key)
	if err != nil {
		if errors.Is(err, pebble.ErrNotFound) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("pebble get failed: %w", err)
	}

	// Make a copy of the value since it's only valid while closer is open
	result := make([]byte, len(value))
	copy(result, value)

	if err := closer.Close(); err != nil {
		return result, nil
	}

	return result, nil
}

func (p *KVStore) Put(key, value []byte) error {
	if p.closed.Load() {
		return ErrClosed
	}
	return p.db.Set(key, value, pebble.Sync)
}

func (p *KVStore) Delete(key []byte) error {
	if p.closed.Load() {
		return ErrClosed
	}
	return p.db.Delete(key, pebble.Sync)
}

func (p *KVStore) Close() error {
	if !p.closed.CompareAndSwap(false, true) {
		return nil
	}
	return p.db.Close()
}
