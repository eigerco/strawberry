package state

import (
	"fmt"
	"testing"

	"github.com/eigerco/strawberry/internal/block"
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/jamtime"
	"github.com/eigerco/strawberry/internal/safrole"
	"github.com/eigerco/strawberry/internal/testutils"
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
		 if i % 2 == 0 {
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

func setupValidatorState(t *testing.T) *ValidatorState {
	validatorState := ValidatorState{}
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
