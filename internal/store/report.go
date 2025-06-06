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
func (r *WorkReport) PutWorkReport(report block.WorkReport) error {
	h, err := report.Hash()
	if err != nil {
		return fmt.Errorf("hash work-report: %w", err)
	}

	b, err := report.Encode()
	if err != nil {
		return fmt.Errorf("marshal work-report: %w", err)
	}

	err = r.Put(makeKey(prefixWorkReport, h[:]), b)
	if err != nil {
		return fmt.Errorf("put work-report: %w", err)
	}

	return nil
}

// GetWorkReport fetches a work-report by hash.
func (r *WorkReport) GetWorkReport(h crypto.Hash) (block.WorkReport, error) {
	b, err := r.Get(makeKey(prefixWorkReport, h[:]))
	if err != nil {
		if errors.Is(err, pebble.ErrNotFound) {
			return block.WorkReport{}, ErrWorkReportNotFound
		}
		return block.WorkReport{}, fmt.Errorf("get work-report: %w", err)
	}

	var report block.WorkReport
	err = jam.Unmarshal(b, &report)
	if err != nil {
		return block.WorkReport{}, fmt.Errorf("unmarshal work-report: %w", err)
	}

	return report, nil
}

func (r *WorkReport) DeleteWorkReport(h crypto.Hash) error {
	return r.Delete(makeKey(prefixWorkReport, h[:]))
}
