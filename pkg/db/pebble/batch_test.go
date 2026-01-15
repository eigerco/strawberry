package pebble

import (
	"github.com/eigerco/strawberry/pkg/db"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestBatch(t *testing.T) {
	tests := []struct {
		name string
		fn   func(t *testing.T, store db.KVStore)
	}{
		{
			name: "basic_batch_operations",
			fn:   testBasicBatchOperations,
		},
		{
			name: "batch_commit_closure",
			fn:   testBatchCommitAndClose,
		},
		{
			name: "multiple_batches",
			fn:   testMultipleBatches,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			store, err := NewKVStore()
			require.NoError(t, err)
			defer store.Close() //nolint:errcheck // TODO: handle error

			tc.fn(t, store)
		})
	}
}

func testBasicBatchOperations(t *testing.T, store db.KVStore) {
	batch := store.NewBatch()
	defer batch.Close() //nolint:errcheck // TODO: handle error

	// Test batch Put operations
	keys := [][]byte{[]byte("key1"), []byte("key2"), []byte("key3")}
	values := [][]byte{[]byte("value1"), []byte("value2"), []byte("value3")}

	for i := range keys {
		err := batch.Put(keys[i], values[i])
		require.NoError(t, err)
	}

	// Delete one key in the same batch
	err := batch.Delete(keys[1])
	require.NoError(t, err)

	// Commit batch
	err = batch.Commit()
	require.NoError(t, err)

	// Verify values
	val1, err := store.Get(keys[0])
	require.NoError(t, err)
	assert.Equal(t, values[0], val1)

	// Verify deleted key
	_, err = store.Get(keys[1])
	assert.ErrorIs(t, err, ErrNotFound)

	val3, err := store.Get(keys[2])
	require.NoError(t, err)
	assert.Equal(t, values[2], val3)
}

func testBatchCommitAndClose(t *testing.T, store db.KVStore) {
	batch := store.NewBatch()

	// Add some operations
	err := batch.Put([]byte("key"), []byte("value"))
	require.NoError(t, err)

	// Commit batch
	err = batch.Commit()
	require.NoError(t, err)

	// Operations after commit should fail
	err = batch.Put([]byte("key2"), []byte("value2"))
	assert.ErrorIs(t, err, ErrBatchDone)

	err = batch.Delete([]byte("key2"))
	assert.ErrorIs(t, err, ErrBatchDone)

	// Second commit should fail
	err = batch.Commit()
	assert.ErrorIs(t, err, ErrBatchDone)

	// Close should not error
	err = batch.Close()
	assert.NoError(t, err)

	// Double close should not error
	err = batch.Close()
	assert.NoError(t, err)
}

func testMultipleBatches(t *testing.T, store db.KVStore) {
	batch1 := store.NewBatch()
	batch2 := store.NewBatch()
	defer batch1.Close() //nolint:errcheck // TODO: handle error
	defer batch2.Close() //nolint:errcheck // TODO: handle error

	// Write to both batches
	err := batch1.Put([]byte("key1"), []byte("batch1"))
	require.NoError(t, err)
	err = batch2.Put([]byte("key2"), []byte("batch2"))
	require.NoError(t, err)

	// Commit both batches
	err = batch1.Commit()
	require.NoError(t, err)
	err = batch2.Commit()
	require.NoError(t, err)

	// Verify both writes succeeded
	val1, err := store.Get([]byte("key1"))
	require.NoError(t, err)
	assert.Equal(t, []byte("batch1"), val1)

	val2, err := store.Get([]byte("key2"))
	require.NoError(t, err)
	assert.Equal(t, []byte("batch2"), val2)
}
