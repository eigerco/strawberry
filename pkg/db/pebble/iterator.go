package pebble

import (
	"fmt"
	"github.com/cockroachdb/pebble"
	"github.com/eigerco/strawberry/pkg/db"
)

type Iterator struct {
	iter *pebble.Iterator
}

func (p *KVStore) NewIterator(start, end []byte) (db.Iterator, error) {
	iter, err := p.db.NewIter(&pebble.IterOptions{
		LowerBound: start,
		UpperBound: end,
	})
	if err != nil {
		return nil, fmt.Errorf(ErrInIteratorCreation, err)
	}
	return &Iterator{iter: iter}, nil
}

func (it *Iterator) Next() bool {
	// If the iterator is un-positioned, position it at the first key
	if !it.iter.Valid() {
		return it.iter.First()
	}
	// Otherwise, move to the next key
	return it.iter.Next()
}

func (it *Iterator) Key() []byte {
	key := it.iter.Key()
	result := make([]byte, len(key))
	copy(result, key)
	return result
}

func (it *Iterator) Value() ([]byte, error) {
	if !it.iter.Valid() {
		return nil, ErrIteratorInvalid
	}

	val, err := it.iter.ValueAndErr()
	if err != nil {
		return nil, fmt.Errorf(ErrIteratorValue, err)
	}

	result := make([]byte, len(val))
	copy(result, val)
	return result, nil
}

func (it *Iterator) Valid() bool {
	return it.iter.Valid()
}

func (it *Iterator) Close() error {
	return it.iter.Close()
}
