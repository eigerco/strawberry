package pebble

import (
	"github.com/eigerco/strawberry/pkg/db"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestKVStore(t *testing.T) {
	tests := []struct {
		name string
		fn   func(t *testing.T, store db.KVStore)
	}{
		{
			name: "basic_put_get",
			fn:   testBasicPutGet,
		},
		{
			name: "delete_operations",
			fn:   testDelete,
		},
		{
			name: "store_closure",
			fn:   testStoreClosure,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			store, err := NewKVStore()
			require.NoError(t, err)
			defer store.Close()

			tc.fn(t, store)
		})
	}
}

func testBasicPutGet(t *testing.T, store db.KVStore) {
	key := []byte("test-key")
	value := []byte("test-value")

	err := store.Put(key, value)
	require.NoError(t, err)

	retrieved, err := store.Get(key)
	require.NoError(t, err)
	assert.Equal(t, value, retrieved)

	// Test non-existent key
	_, err = store.Get([]byte("non-existent"))
	assert.ErrorIs(t, err, ErrNotFound)
}

func testDelete(t *testing.T, store db.KVStore) {
	key := []byte("delete-test")
	value := []byte("to-be-deleted")

	err := store.Put(key, value)
	require.NoError(t, err)

	err = store.Delete(key)
	require.NoError(t, err)

	_, err = store.Get(key)
	assert.ErrorIs(t, err, ErrNotFound)

	// Delete non-existent key should not error
	err = store.Delete([]byte("non-existent"))
	assert.NoError(t, err)
}

func testStoreClosure(t *testing.T, store db.KVStore) {
	err := store.Close()
	require.NoError(t, err)

	// Test operations after close
	_, err = store.Get([]byte("key"))
	assert.ErrorIs(t, err, ErrClosed)

	err = store.Put([]byte("key"), []byte("value"))
	assert.ErrorIs(t, err, ErrClosed)

	err = store.Delete([]byte("key"))
	assert.ErrorIs(t, err, ErrClosed)

	// Double close should not error
	err = store.Close()
	assert.NoError(t, err)
}
