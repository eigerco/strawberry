package pebble

import (
	"github.com/eigerco/strawberry/pkg/db"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestIterator(t *testing.T) {
	tests := []struct {
		name string
		fn   func(t *testing.T, store db.KVStore)
	}{
		{
			name: "full_range_iteration",
			fn:   testFullRangeIteration,
		},
		{
			name: "bounded_range_iteration",
			fn:   testBoundedRangeIteration,
		},
		{
			name: "iterator_validity",
			fn:   testIteratorValidity,
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

func testFullRangeIteration(t *testing.T, store db.KVStore) {
	// Prepare data
	data := map[string]string{
		"a": "value-a",
		"b": "value-b",
		"c": "value-c",
		"d": "value-d",
	}

	for k, v := range data {
		err := store.Put([]byte(k), []byte(v))
		require.NoError(t, err)
	}

	// Test full range iteration
	iter, err := store.NewIterator(nil, nil)
	require.NoError(t, err)
	defer iter.Close() //nolint:errcheck // TODO: handle error

	count := 0
	// First position the iterator at the start
	if iter.Next() {
		count++
		value, err := iter.Value()
		require.NoError(t, err)

		expectedValue, exists := data[string(iter.Key())]
		assert.True(t, exists)
		assert.Equal(t, []byte(expectedValue), value)

		// Then continue with the rest
		for iter.Next() {
			value, err := iter.Value()
			require.NoError(t, err)

			expectedValue, exists := data[string(iter.Key())]
			assert.True(t, exists)
			assert.Equal(t, []byte(expectedValue), value)
			count++
		}
	}
	assert.Equal(t, len(data), count)
}

func testBoundedRangeIteration(t *testing.T, store db.KVStore) {
	// Prepare data
	data := map[string]string{
		"a": "value-a",
		"b": "value-b",
		"c": "value-c",
		"d": "value-d",
		"e": "value-e",
	}

	for k, v := range data {
		err := store.Put([]byte(k), []byte(v))
		require.NoError(t, err)
	}

	// Test bounded range iteration (b to d)
	iter, err := store.NewIterator([]byte("b"), []byte("e"))
	require.NoError(t, err)
	defer iter.Close() //nolint:errcheck // TODO: handle error

	expected := map[string]string{
		"b": "value-b",
		"c": "value-c",
		"d": "value-d",
	}

	count := 0
	if iter.Next() {
		count++
		value, err := iter.Value()
		require.NoError(t, err)

		expectedValue, exists := expected[string(iter.Key())]
		assert.True(t, exists)
		assert.Equal(t, []byte(expectedValue), value)

		for iter.Next() {
			value, err := iter.Value()
			require.NoError(t, err)

			expectedValue, exists := expected[string(iter.Key())]
			assert.True(t, exists)
			assert.Equal(t, []byte(expectedValue), value)
			count++
		}
	}
	assert.Equal(t, len(expected), count)
}

func testIteratorValidity(t *testing.T, store db.KVStore) {
	// Prepare a few key-value pairs to ensure proper iteration
	testData := map[string]string{
		"key1": "value1",
		"key2": "value2",
	}

	for k, v := range testData {
		err := store.Put([]byte(k), []byte(v))
		require.NoError(t, err)
	}

	iter, err := store.NewIterator(nil, nil)
	require.NoError(t, err)
	defer iter.Close() //nolint:errcheck // TODO: handle error

	// Initial state - iterator is not positioned
	assert.False(t, iter.Valid())

	// First Next() should position at first element
	assert.True(t, iter.Next())
	assert.True(t, iter.Valid())

	val, err := iter.Value()
	require.NoError(t, err)
	assert.Contains(t, testData, string(iter.Key()))
	assert.Equal(t, testData[string(iter.Key())], string(val))

	// Should be able to move to second element
	assert.True(t, iter.Next())
	assert.True(t, iter.Valid())

	val, err = iter.Value()
	require.NoError(t, err)
	assert.Contains(t, testData, string(iter.Key()))
	assert.Equal(t, testData[string(iter.Key())], string(val))

	// No more elements
	assert.False(t, iter.Next())
	assert.False(t, iter.Valid())

	// Value() should error when invalid
	_, err = iter.Value()
	assert.ErrorIs(t, err, ErrIteratorInvalid)
}
