package pebble

import "errors"

var (
	ErrClosed          = errors.New("db is closed")
	ErrNotFound        = errors.New("key not found")
	ErrBatchDone       = errors.New("batch is already committed or closed")
	ErrIteratorInvalid = errors.New("iterator is not valid")

	ErrInIteratorCreation = "failed to create iterator with error %w"
	ErrIteratorValue      = "iterator value errored with %w"
)
