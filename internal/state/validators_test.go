package state

import (
	"fmt"
	"testing"

	"github.com/eigerco/strawberry/internal/block"
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/jamtime"
	"github.com/eigerco/strawberry/internal/safrole"
	"github.com/eigerco/strawberry/internal/testutils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDetermineNewSealingKeysWhenNotFirstTimeslot(t *testing.T) {
	vs := setupValidatorState(t)
	beforeSealingKeys := vs.SafroleState.SealingKeySeries
	epochMarker := block.EpochMarker{}
	epochMarker.Entropy = testutils.RandomHash(t)
	for i := uint16(0); i < block.NumberOfValidators; i++ {
		epochMarker.Keys[i] = testutils.RandomBandersnatchPublicKey(t)
	}
	header := block.Header{
		TimeSlotIndex: 2,
		EpochMarker:   &epochMarker,
	}
	block := &block.Block{
		Header: &header,
	}
	err := vs.UpdateSealingKeys(block)
	require.NoError(t, err)
	// It should change nothing because it is not the first timeslot of the epoch
	require.Equal(t, beforeSealingKeys, vs.SafroleState.SealingKeySeries)
}

func TestDetermineNewSealingKeysWhenNotEnoughTickets(t *testing.T) {
	vs := setupValidatorState(t)
	vs.SafroleState.TicketAccumulator = vs.SafroleState.TicketAccumulator[:len(vs.SafroleState.TicketAccumulator)/2]
	epochMarker := block.EpochMarker{}
	epochMarker.Entropy = testutils.RandomHash(t)
	for i := uint16(0); i < block.NumberOfValidators; i++ {
		epochMarker.Keys[i] = testutils.RandomBandersnatchPublicKey(t)
	}
	header := block.Header{
		TimeSlotIndex: 0,
		EpochMarker:   &epochMarker,
	}
	block := &block.Block{
		Header: &header,
	}
	err := vs.UpdateSealingKeys(block)
	require.NoError(t, err)
	value, err := vs.SafroleState.SealingKeySeries.Value()
	require.NoError(t, err)
	fallbackKeys, ok := value.(crypto.EpochKeys)
	require.True(t, ok, "Result should be EpochKeys for fallback case")
	require.Len(t, value, int(jamtime.TimeslotsPerEpoch), "Should have correct number of fallback keys")
	// Verify that the keys are derived from the epochMarker
	for _, key := range fallbackKeys {
		require.Contains(t, epochMarker.Keys, key, "Fallback key should be from epochMarker.Keys")
	}
}
func TestDetermineNewSealingKeys(t *testing.T) {
	vs := setupValidatorState(t)
	epochMarker := block.EpochMarker{}
	epochMarker.Entropy = testutils.RandomHash(t)
	for i := uint16(0); i < block.NumberOfValidators; i++ {
		epochMarker.Keys[i] = testutils.RandomBandersnatchPublicKey(t)
	}
	header := block.Header{
		TimeSlotIndex: 0,
		EpochMarker:   &epochMarker,
	}
	block := &block.Block{
		Header: &header,
	}
	err := vs.UpdateSealingKeys(block)
	require.NoError(t, err)
	value, err := vs.SafroleState.SealingKeySeries.Value()
	require.NoError(t, err)
	ticketBodies, ok := value.(safrole.TicketsBodies)
	require.True(t, ok, "Result should be TicketsBodies for sufficient tickets case")
	require.Len(t, ticketBodies, int(jamtime.TimeslotsPerEpoch), "Should have correct number of tickets")

	// Verify the sequence
	n := len(vs.SafroleState.TicketAccumulator)
	for i := 0; i < n; i++ {
		if i%2 == 0 {
			// Even indices should match tickets from the start of the original sequence
			require.Equal(t, vs.SafroleState.TicketAccumulator[i/2], ticketBodies[i],
				fmt.Sprintf("Ticket at position %d should match original ticket at %d", i, i/2))
		} else {
			// Odd indices should match tickets from the end of the original sequence, in reverse order
			require.Equal(t, vs.SafroleState.TicketAccumulator[n-1-(i/2)], ticketBodies[i],
				fmt.Sprintf("Ticket at position %d should match original ticket at %d", i, n-1-(i/2)))
		}
	}
}

func TestRotateValidatorKeysWhenNotNewEpoch(t *testing.T) {
	vs := setupValidatorState(t)
	header := block.Header{
		TimeSlotIndex: 2,
	}
	block := &block.Block{
		Header: &header,
	}

	initialValidators := vs.Validators
	initialNextValidators := vs.SafroleState.NextValidators
	initialQueuedValidators := vs.QueuedValidators

	// Execute
	err := vs.RotateValidators(block)
	require.NoError(t, err)

	// Assert that nothing has changed
	assert.Equal(t, initialValidators, vs.Validators, "Validators should remain unchanged")
	assert.Equal(t, initialNextValidators, vs.SafroleState.NextValidators, "SafroleState.NextValidators should remain unchanged")
	assert.Equal(t, initialQueuedValidators, vs.QueuedValidators, "QueuedValidators should remain unchanged")
}

func TestRotateValidatorKeys(t *testing.T) {
	vs := setupValidatorState(t)
	offender := vs.QueuedValidators[0]

	header := block.Header{
		TimeSlotIndex: 0,
		OffendersMarkers: []crypto.Ed25519PublicKey{
			offender.Ed25519,
		},
	}
	block := &block.Block{
		Header: &header,
	}
	// Store initial state for comparison
	initialValidators := vs.Validators
	initialNextValidators := vs.SafroleState.NextValidators
	initialQueuedValidators := vs.QueuedValidators

	// Execute
	err := vs.RotateValidators(block)

	require.NoError(t, err)
	// Check that the offender has not been added to the SafroleState.NextValidators
	assert.NotContains(t, vs.SafroleState.NextValidators, offender, "Offender should be removed from s.SafroleState.NextValidators")
	assert.Equal(t, crypto.ValidatorKey{}, vs.SafroleState.NextValidators[0], "The first element of SafroleState.NextValidators should be the zero value")

	// Check that the sets are different from each other before rotation
	assert.NotEqual(t, vs.ArchivedValidators, vs.Validators, "ArchivedValidators should differ from current Validators")
	assert.NotEqual(t, vs.Validators, vs.SafroleState.NextValidators, "Validators should differ from SafroleState.NextValidators")
	assert.NotEqual(t, vs.ArchivedValidators, vs.SafroleState.NextValidators, "ArchivedValidators should differ from SafroleState.NextValidators")

	// Check that the validators have rotated correctly
	assert.Equal(t, initialValidators, vs.ArchivedValidators, "ArchivedValidators should be the previous Validators")
	assert.Equal(t, initialNextValidators, vs.Validators, "Validators should be the previous NextValidators")
	assert.Equal(t, initialQueuedValidators[1:], vs.SafroleState.NextValidators[1:], "SafroleState.NextValidators should be the previous QueuedValidators excluding the first element")
	assert.Empty(t, vs.QueuedValidators, "QueuedValidators should be empty after rotation")

	// TODO add test for ring commitment when implemented
}

func setupValidatorState(t *testing.T) *ValidatorState {
	validatorState := ValidatorState{}
	validatorState.Validators = randomListOfValidators(t)
	validatorState.QueuedValidators = randomListOfValidators(t)
	validatorState.ArchivedValidators = randomListOfValidators(t)
	safroleState := safrole.State{}
	safroleState.TicketAccumulator = make([]block.Ticket, jamtime.TimeslotsPerEpoch)
	for i := 0; i < jamtime.TimeslotsPerEpoch; i++ {
		safroleState.TicketAccumulator[i] = randomTicket(t)
	}
	safroleState.SealingKeySeries = safrole.TicketsOrKeys{}
	var epochKeys crypto.EpochKeys
	for i := 0; i < jamtime.TimeslotsPerEpoch; i++ {
		epochKeys[i] = testutils.RandomBandersnatchPublicKey(t)
	}
	validatorState.SafroleState = safroleState
	err := safroleState.SealingKeySeries.SetValue(epochKeys)
	require.NoError(t, err)
	return &validatorState
}

func randomTicket(t *testing.T) block.Ticket {
	return block.Ticket{
		Identifier: testutils.RandomHash(t),
		EntryIndex: uint8(0),
	}
}

func randomListOfValidators(t *testing.T) safrole.ValidatorsData {
	var validators safrole.ValidatorsData
	for i := uint16(0); i < 2; i++ {
		validators[i] = testutils.RandomValidatorKey(t)
	}
	return validators
}
