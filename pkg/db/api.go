package kv_store

// KVStore provides a minimal key-value store interface
type KVStore interface {
	Get(key []byte) ([]byte, error)
	Put(key []byte, value []byte) error
	Delete(key []byte) error
	NewBatch() Batch
	NewIterator(start, end []byte) Iterator
	Close() error
}

type Batch interface {
	Put(key []byte, err error) error
	Delete(key []byte) error
	Commit() error
	Close() error
}

type Iterator interface {
	Next() bool
	Key() []byte
	Value() []byte
	Valid() bool
	Close() error
}
