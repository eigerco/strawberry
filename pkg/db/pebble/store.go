package kv_store

import (
	"github.com/cockroachdb/pebble"
	"sync"
)

type PebbleStore struct {
	db     *pebble.DB
	closed bool
	mu     sync.RWMutex
}

func NewPebbleStore(path string) (*PebbleStore, error) {
	opts := &pebble.Options{
		Cache:            pebble.NewCache(64 * 1024 * 1024), // 64MB
		MemTableSize:     32 * 1024 * 1024,                  // 32MB
		MaxMemTableTotal: 128 * 1024 * 1024,                 // 128MB
	}

	db, err := pebble.Open(path, opts)
	if err != nil {
		return nil, err
	}

	return &PebbleStore{db: db}, nil
}

func (p *PebbleStore) Get(key []byte) ([]byte, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if p.closed {
		return nil, ErrClosed
	}

	value, closer, err := p.db.Get(key)
	if err == pebble.ErrNotFound {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	defer closer.Close()

	result := make([]byte, len(value))
	copy(result, value)
	return result, nil
}

func (p *PebbleStore) Put(key, value []byte) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.closed {
		return ErrClosed
	}

	return p.db.Set(key, value, pebble.Sync)
}

func (p *PebbleStore) Delete(key []byte) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.closed {
		return ErrClosed
	}

	return p.db.Delete(key, pebble.Sync)
}

func (p *PebbleStore) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.closed {
		return nil
	}
	p.closed = true
	return p.db.Close()
}
