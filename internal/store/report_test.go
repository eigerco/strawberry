package store

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/eigerco/strawberry/internal/block"
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/testutils"
	"github.com/eigerco/strawberry/pkg/db/pebble"
)

func TestWorkReportStore(t *testing.T) {
	db, err := pebble.NewKVStore()
	require.NoError(t, err)

	reportStore := NewWorkReport(db)
	defer func() {
		err := db.Close()
		require.NoError(t, err, "failed to close db")
	}()

	workReport := block.WorkReport{
		WorkPackageSpecification: block.WorkPackageSpecification{WorkPackageHash: testutils.RandomHash(t)},
		RefinementContext: block.RefinementContext{
			Anchor:                  block.RefinementContextAnchor{HeaderHash: testutils.RandomHash(t)},
			LookupAnchor:            block.RefinementContextLookupAnchor{HeaderHash: testutils.RandomHash(t), Timeslot: testutils.RandomTimeslot()},
			PrerequisiteWorkPackage: nil,
		},
		CoreIndex:         1,
		AuthorizerHash:    testutils.RandomHash(t),
		Output:            []byte("output"),
		SegmentRootLookup: make(map[crypto.Hash]crypto.Hash),
		WorkResults: []block.WorkResult{
			{
				ServiceId:              1,
				ServiceHashCode:        testutils.RandomHash(t),
				PayloadHash:            testutils.RandomHash(t),
				GasPrioritizationRatio: uint64(20),
				Output:                 block.WorkResultOutputOrError{Inner: []byte("output")},
			},
		},
	}

	err = reportStore.PutWorkReport(workReport)
	require.NoError(t, err)

	hash, err := workReport.Hash()
	require.NoError(t, err)

	actual, err := reportStore.GetWorkReport(hash)
	require.NoError(t, err)

	require.Equal(t, workReport, actual)

	err = reportStore.DeleteWorkReport(hash)
	require.NoError(t, err)

	_, err = reportStore.GetWorkReport(hash)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrWorkReportNotFound)
}
