package trie

import (
	"fmt"
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/pkg/db"
	"github.com/eigerco/strawberry/pkg/db/pebble"
	"sync"
)

// DB represents a Patricia-Merkle trie db
type DB struct {
	store    db.KVStore
	root     crypto.Hash
	rootLock sync.RWMutex
}

// NewDB creates a new trie db
func NewDB() (*DB, error) {
	store, err := pebble.NewKVStore()
	if err != nil {
		return nil, fmt.Errorf(ErrFailedStoreInit, err)
	}
	tdb := &DB{
		store: store,
	}
	return tdb, err
}

// MerklizeAndCommit writes a series of key-value pairs to the trie
func (s *DB) MerklizeAndCommit(pairs [][2][]byte) (crypto.Hash, error) {
	s.rootLock.Lock()
	defer s.rootLock.Unlock()

	batch := s.store.NewBatch()
	defer func(batch db.Batch) {
		err := batch.Close()
		if err != nil {
			panic(fmt.Sprintf(ErrFailedBatchCommit, err))
		}
	}(batch)

	root, err := Merklize(pairs, 0, func(hash crypto.Hash, node Node) error {
		return batch.Put(hash[:], node[:])
	})
	if err != nil {
		return crypto.Hash{}, err
	}

	if err := batch.Commit(); err != nil {
		return crypto.Hash{}, err
	}

	s.root = root
	return root, nil
}

func (s *DB) Get(hash crypto.Hash) (Node, error) {
	data, err := s.store.Get(hash[:])
	if err != nil {
		return Node{}, err
	}
	return Node(data), nil
}

func (s *DB) Root() crypto.Hash {
	s.rootLock.RLock()
	defer s.rootLock.RUnlock()
	return s.root
}

func (s *DB) Close() error {
	return s.store.Close()
}
