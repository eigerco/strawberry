package safrole

import (
	"fmt"

	"github.com/eigerco/strawberry/pkg/serialization/codec/jam"

	"github.com/eigerco/strawberry/internal/block"
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/jamtime"
)

type TicketsBodies [jamtime.TimeslotsPerEpoch]block.Ticket

func (t TicketsBodies) TicketsOrKeysType() {}

// TicketAccumulator is enum/union that represents ya. It should contain either
// TicketBodies which is an array of tickets, or in the fallback case
// crypto.EpochKeys, an array of bandersnatch public keys.
type TicketAccumulator struct {
	inner TicketsOrKeys
}

// TicketsOrKeys represents the union of either TicketBodies or
// crypto.EpochKeys.
type TicketsOrKeys interface {
	TicketsOrKeysType()
}

func (ta *TicketAccumulator) Set(value TicketsOrKeys) {
	ta.inner = value
}

func (ta *TicketAccumulator) Get() TicketsOrKeys {
	return ta.inner
}

func (ta *TicketAccumulator) SetValue(value any) error {
	switch value := value.(type) {
	case crypto.EpochKeys:
		ta.inner = value
		return nil
	case TicketsBodies:
		ta.inner = value
		return nil
	default:
		return fmt.Errorf(jam.ErrUnsupportedType, value)
	}
}

func (ta TicketAccumulator) IndexValue() (uint, any, error) {
	switch ta.inner.(type) {
	case crypto.EpochKeys:
		return 1, ta.inner, nil
	case TicketsBodies:
		return 0, ta.inner, nil
	}
	return 0, nil, jam.ErrUnsupportedEnumTypeValue
}

func (ta TicketAccumulator) Value() (value any, err error) {
	_, value, err = ta.IndexValue()
	return
}

func (ta TicketAccumulator) ValueAt(index uint) (any, error) {
	switch index {
	case 1:
		return crypto.EpochKeys{}, nil
	case 0:
		return TicketsBodies{}, nil
	}
	return nil, jam.ErrUnsupportedEnumTypeValue
}
