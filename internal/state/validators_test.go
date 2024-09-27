package state

import (
	"testing"

	"github.com/eigerco/strawberry/internal/block"
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/jamtime"
	"github.com/eigerco/strawberry/internal/safrole"
	"github.com/eigerco/strawberry/internal/testutils"
	"github.com/stretchr/testify/require"
)

func setupValidatorState(t *testing.T) *ValidatorState {
	validatorState := ValidatorState{}
	validatorState.Validators = randomListOfValidators(t)
	validatorState.QueuedValidators = randomListOfValidators(t)
	validatorState.ArchivedValidators = randomListOfValidators(t)
	safroleState := safrole.State{}
	safroleState.NextValidators = randomListOfValidators(t)
	safroleState.TicketAccumulator = make([]block.Ticket, jamtime.TimeslotsPerEpoch)
	for i := 0; i < jamtime.TimeslotsPerEpoch; i++ {
		safroleState.TicketAccumulator[i] = randomTicket(t)
	}
	safroleState.SealingKeySeries = safrole.TicketsOrKeys{}
	var epochKeys crypto.EpochKeys
	for i := 0; i < jamtime.TimeslotsPerEpoch; i++ {
		epochKeys[i] = testutils.RandomBandersnatchPublicKey(t)
	}
	err := safroleState.SealingKeySeries.SetValue(epochKeys)
	validatorState.SafroleState = safroleState
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
