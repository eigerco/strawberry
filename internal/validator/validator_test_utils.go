package validator

import (
	"testing"

	"github.com/eigerco/strawberry/internal/block"
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/jamtime"
	"github.com/eigerco/strawberry/internal/safrole"
	"github.com/eigerco/strawberry/internal/testutils"
)

func SetupValidatorState(t *testing.T) *ValidatorState {
	validatorState := ValidatorState{}
	validatorState.CurrentValidators = RandomListOfValidators(t)
	validatorState.QueuedValidators = RandomListOfValidators(t)
	validatorState.ArchivedValidators = RandomListOfValidators(t)
	safroleState := safrole.State{}
	safroleState.NextValidators = RandomListOfValidators(t)
	safroleState.TicketAccumulator = make([]block.Ticket, jamtime.TimeslotsPerEpoch)
	for i := 0; i < jamtime.TimeslotsPerEpoch; i++ {
		safroleState.TicketAccumulator[i] = RandomTicket(t)
	}
	safroleState.SealingKeySeries = safrole.SealingKeys{}
	var epochKeys crypto.EpochKeys
	for i := 0; i < jamtime.TimeslotsPerEpoch; i++ {
		epochKeys[i] = testutils.RandomBandersnatchPublicKey(t)
	}
	safroleState.SealingKeySeries.Set(epochKeys)
	validatorState.SafroleState = safroleState
	return &validatorState
}

func RandomTicket(t *testing.T) block.Ticket {
	return block.Ticket{
		Identifier: testutils.RandomBandersnatchOutputHash(t),
		EntryIndex: uint8(0),
	}
}

func RandomListOfValidators(t *testing.T) safrole.ValidatorsData {
	var validators safrole.ValidatorsData
	for i := uint16(0); i < 2; i++ {
		validators[i] = testutils.RandomValidatorKey(t)
	}
	return validators
}
