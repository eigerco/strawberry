package kv_store

import "github.com/cockroachdb/pebble"

type PebbleIterator struct {
	iter *pebble.Iterator
}

func (p *PebbleStore) NewIterator(start, end []byte) Iterator {
	return &PebbleIterator{
		iter: p.db.NewIter(&pebble.IterOptions{
			LowerBound: start,
			UpperBound: end,
		}),
	}
}

func (it *PebbleIterator) Next() bool {
	return it.iter.Next()
}

func (it *PebbleIterator) Key() []byte {
	key := it.iter.Key()
	result := make([]byte, len(key))
	copy(result, key)
	return result
}

func (it *PebbleIterator) Value() []byte {
	val := it.iter.Value()
	result := make([]byte, len(val))
	copy(result, val)
	return result
}

func (it *PebbleIterator) Valid() bool {
	return it.iter.Valid()
}

func (it *PebbleIterator) Close() error {
	return it.iter.Close()
}
