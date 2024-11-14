package db

// KVStore represents a key-value storage interface providing basic operations
// for data manipulation and iteration.
type KVStore interface {
	Get(key []byte) ([]byte, error)
	Put(key []byte, value []byte) error
	Delete(key []byte) error
	NewBatch() Batch
	NewIterator(start, end []byte) (Iterator, error)
	Close() error
}

// Batch represents an atomic batch of operations.
// All operations in a batch are performed atomically.
type Batch interface {
	Put(key []byte, value []byte) error
	Delete(key []byte) error
	Commit() error
	Close() error
}

// Iterator provides sequential access over a range of key-value pairs.
// Iterators must be closed after use.
type Iterator interface {
	Next() bool
	Key() []byte
	Value() ([]byte, error)
	Valid() bool
	Close() error
}
