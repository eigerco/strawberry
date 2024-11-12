package kv_store

import "errors"

var (
	ErrClosed   = errors.New("kv-store: database is closed")
	ErrNotFound = errors.New("kv-store: key not found")
)
