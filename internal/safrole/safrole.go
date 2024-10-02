package safrole

import (
	"fmt"
	"github.com/eigerco/strawberry/pkg/serialization/codec/jam"

	"github.com/ChainSafe/gossamer/pkg/scale"
	"github.com/eigerco/strawberry/internal/block"
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/jamtime"
)

type TicketsBodies [jamtime.TimeslotsPerEpoch]block.Ticket

// TicketsOrKeys is enum
type TicketsOrKeys struct {
	inner any
}

type TicketsOrKeysValues interface {
	crypto.EpochKeys | TicketsBodies
}

func setTicketsOrKeys[Value TicketsOrKeysValues](tok *TicketsOrKeys, value Value) {
	tok.inner = value
}

func (tok *TicketsOrKeys) SetValue(value any) error {
	switch value := value.(type) {
	case crypto.EpochKeys:
		setTicketsOrKeys(tok, value)
		return nil
	case TicketsBodies:
		setTicketsOrKeys(tok, value)
		return nil
	default:
		return fmt.Errorf(jam.ErrUnsupportedType, value)
	}
}

func (tok TicketsOrKeys) IndexValue() (uint, any, error) {
	switch tok.inner.(type) {
	case crypto.EpochKeys:
		return 1, tok.inner, nil
	case TicketsBodies:
		return 0, tok.inner, nil
	}
	return 0, nil, jam.ErrUnsupportedEnumTypeValue
}

func (tok TicketsOrKeys) Value() (value any, err error) {
	_, value, err = tok.IndexValue()
	return
}

func (tok TicketsOrKeys) ValueAt(index uint) (any, error) {
	switch index {
	case 1:
		return crypto.EpochKeys{}, nil
	case 0:
		return TicketsBodies{}, nil
	}
	return nil, scale.ErrUnknownVaryingDataTypeValue
}
