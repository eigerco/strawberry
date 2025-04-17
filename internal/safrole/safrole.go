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

// SealingKeys is enum/union that represents ys. It should contain either
// TicketBodies which is an array of tickets, or in the fallback case
// crypto.EpochKeys, an array of bandersnatch public keys.
type SealingKeys struct {
	inner TicketsOrKeys
}

// TicketsOrKeys represents the union of either TicketBodies or
// crypto.EpochKeys.
type TicketsOrKeys interface {
	TicketsOrKeysType()
}

func (sk *SealingKeys) Set(value TicketsOrKeys) {
	sk.inner = value
}

func (sk *SealingKeys) Get() TicketsOrKeys {
	return sk.inner
}

func (sk *SealingKeys) SetValue(value any) error {
	switch value := value.(type) {
	case crypto.EpochKeys:
		sk.inner = value
		return nil
	case TicketsBodies:
		sk.inner = value
		return nil
	default:
		return fmt.Errorf(jam.ErrUnsupportedType, value)
	}
}

func (sk SealingKeys) IndexValue() (uint, any, error) {
	switch sk.inner.(type) {
	case crypto.EpochKeys:
		return 1, sk.inner, nil
	case TicketsBodies:
		return 0, sk.inner, nil
	}
	return 0, nil, jam.ErrUnsupportedEnumTypeValue
}

func (sk SealingKeys) Value() (value any, err error) {
	_, value, err = sk.IndexValue()
	return
}

func (sk SealingKeys) ValueAt(index uint) (any, error) {
	switch index {
	case 1:
		return crypto.EpochKeys{}, nil
	case 0:
		return TicketsBodies{}, nil
	}
	return nil, jam.ErrUnsupportedEnumTypeValue
}
