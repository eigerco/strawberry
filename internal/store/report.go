package store

import (
	"errors"
	"fmt"

	"github.com/eigerco/strawberry/internal/block"
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/pkg/db"
	"github.com/eigerco/strawberry/pkg/db/pebble"
	"github.com/eigerco/strawberry/pkg/serialization/codec/jam"
)

var ErrWorkReportNotFound = errors.New("work-report not found")

// WorkReport manages work reports storage using a key-value store
type WorkReport struct {
	db.KVStore
}

// NewWorkReport creates a new work report store using KVStore
func NewWorkReport(db db.KVStore) *WorkReport {
	return &WorkReport{KVStore: db}
}

// PutWorkReport stores a work report in the chain store
func (c *WorkReport) PutWorkReport(r block.WorkReport) error {
	h, err := r.Hash()
	if err != nil {
		return fmt.Errorf("hash work-report: %w", err)
	}

	b, err := r.Encode()
	if err != nil {
		return fmt.Errorf("marshal work-report: %w", err)
	}

	return c.Put(makeKey(prefixWorkReport, h[:]), b)
}

// GetWorkReport fetches a work-report by hash.
func (c *WorkReport) GetWorkReport(h crypto.Hash) (block.WorkReport, error) {
	b, err := c.Get(makeKey(prefixWorkReport, h[:]))
	if err != nil {
		if errors.Is(err, pebble.ErrNotFound) {
			return block.WorkReport{}, ErrWorkReportNotFound
		}
		return block.WorkReport{}, err
	}

	var report block.WorkReport
	err = jam.Unmarshal(b, &report)
	if err != nil {
		return block.WorkReport{}, fmt.Errorf("unmarshal work-report: %w", err)
	}

	return report, nil
}

func (c *WorkReport) DeleteWorkReport(h crypto.Hash) error {
	return c.Delete(makeKey(prefixWorkReport, h[:]))
}
