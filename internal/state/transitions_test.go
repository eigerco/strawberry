package state

import (
	"testing"

	"github.com/eigerco/strawberry/internal/block"
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/jamtime"
	"github.com/eigerco/strawberry/internal/testutils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCalculateNewTimeStateTransiton(t *testing.T) {
	header := block.Header{
		TimeSlotIndex: 2,
	}
	newTimeState := calculateNewTimeState(header)
	require.Equal(t, newTimeState, header.TimeSlotIndex)
}

func TestCalculateNewEntropyPoolWhenNewEpoch(t *testing.T) {
	entropyPool := [4]crypto.Hash{
		testutils.RandomHash(t),
		testutils.RandomHash(t),
		testutils.RandomHash(t),
		testutils.RandomHash(t),
	}
	header := block.Header{
		TimeSlotIndex: 600,
	}
	newEntropyPool, err := calculateNewEntropyPool(header, jamtime.Timeslot(599), entropyPool)
	require.NoError(t, err)
	assert.Equal(t, entropyPool[2], newEntropyPool[3])
	assert.Equal(t, entropyPool[1], newEntropyPool[2])
	assert.Equal(t, entropyPool[0], newEntropyPool[1])
}

func TestCalculateNewEntropyPoolWhenNotNewEpoch(t *testing.T) {
	timeslot := jamtime.Timeslot(600)
	entropyPool := [4]crypto.Hash{
		testutils.RandomHash(t),
		testutils.RandomHash(t),
		testutils.RandomHash(t),
		testutils.RandomHash(t),
	}
	header := block.Header{
		TimeSlotIndex: 601,
	}
	newEntropyPool, err := calculateNewEntropyPool(header, timeslot, entropyPool)
	require.NoError(t, err)
	assert.Equal(t, entropyPool[3], newEntropyPool[3])
	assert.Equal(t, entropyPool[2], newEntropyPool[2])
	assert.Equal(t, entropyPool[1], newEntropyPool[1])
}
func TestCalculateNewValidatorsWhenNewEpoch(t *testing.T) {
	vs := setupValidatorState(t)
	prevNextValidators := vs.SafroleState.NextValidators
	header := block.Header{
		TimeSlotIndex: 600,
	}
	newValidators, err := calculateNewValidators(header, jamtime.Timeslot(599), vs.CurrentValidators, vs.SafroleState.NextValidators)
	require.NoError(t, err)
	require.Equal(t, prevNextValidators, newValidators)
}

func TestCalculateNewValidatorsWhenNotNewEpoch(t *testing.T) {
	vs := setupValidatorState(t)
	prevValidators := vs.CurrentValidators
	header := block.Header{
		TimeSlotIndex: 2,
	}
	newValidators, err := calculateNewValidators(header, jamtime.Timeslot(1), vs.CurrentValidators, vs.SafroleState.NextValidators)
	require.Error(t, err)
	require.Equal(t, prevValidators, newValidators)
}

func TestCalcualteNewArchivedValidatorsWhenNewEpoch(t *testing.T) {
	vs := setupValidatorState(t)
	prevValidators := vs.CurrentValidators
	header := block.Header{
		TimeSlotIndex: 600,
	}
	newArchivedValidators, err := calculateNewArchivedValidators(header, jamtime.Timeslot(599), vs.ArchivedValidators, vs.CurrentValidators)
	require.NoError(t, err)
	require.Equal(t, prevValidators, newArchivedValidators)
}

func TestCalcualteNewArchivedValidatorsWhenNotNewEpoch(t *testing.T) {
	vs := setupValidatorState(t)
	prevArchivedValidators := vs.ArchivedValidators
	header := block.Header{
		TimeSlotIndex: 2,
	}
	newArchivedValidators, err := calculateNewArchivedValidators(header, jamtime.Timeslot(1), vs.ArchivedValidators, vs.CurrentValidators)
	require.Error(t, err)
	require.Equal(t, prevArchivedValidators, newArchivedValidators)
}

func TestCaculateNewSafroleStateWhenNewEpoch(t *testing.T) {
	vs := setupValidatorState(t)
	header := block.Header{
		TimeSlotIndex: 600,
	}
	tickets := block.TicketExtrinsic{}
	expected := vs.SafroleState.NextValidators
	newSafrole, err := calculateNewSafroleState(header, jamtime.Timeslot(599), tickets, expected)
	require.NoError(t, err)
	require.Equal(t, expected, newSafrole.NextValidators)
}

func TestCaculateNewSafroleStateWhenNotNewEpoch(t *testing.T) {
	vs := setupValidatorState(t)
	header := block.Header{
		TimeSlotIndex: 1,
	}
	tickets := block.TicketExtrinsic{}
	queuedValidators := vs.QueuedValidators
	_, err := calculateNewSafroleState(header, jamtime.Timeslot(0), tickets, queuedValidators)
	require.Error(t, err)
}
