package safrole

import (
	"fmt"
	"github.com/ChainSafe/gossamer/pkg/scale"
	"github.com/eigerco/strawberry/internal/block"
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/time"
)

type TicketsBodies [time.TimeslotsPerEpoch]block.Ticket
type TicketsMark [time.TimeslotsPerEpoch]block.Ticket

type CustomErrorCode int

//nolint:unused
var errorCodeMessages = map[CustomErrorCode]string{
	BadSlot:          "bad_slot",
	UnexpectedTicket: "unexpected_ticket",
	BadTicketOrder:   "bad_ticket_order",
	BadTicketProof:   "bad_ticket_proof",
	BadTicketAttempt: "bad_ticket_attempt",
	Reserved:         "reserved",
	DuplicateTicket:  "duplicate_ticket",
}

type Safrole struct {
	Input     Input         `json:"input"`
	PreState  State         `json:"pre_state"`
	Output    OutputOrError `json:"output"`
	PostState State         `json:"post_state"`
}

type Input struct {
	Slot      uint32              `json:"slot"`      // Current slot.
	Entropy   crypto.Hash         `json:"entropy"`   // Per block entropy (originated from block entropy source VRF).
	Extrinsic []block.TicketProof `json:"extrinsic"` // Safrole extrinsic.
}

// TicketsOrKeys is enum
type TicketsOrKeys struct {
	inner any
}

type TicketsOrKeysValues interface {
	EpochKeys | TicketsBodies
}

func setTicketsOrKeys[Value TicketsOrKeysValues](tok *TicketsOrKeys, value Value) {
	tok.inner = value
}

func (tok *TicketsOrKeys) SetValue(value any) (err error) {
	switch value := value.(type) {
	case EpochKeys:
		setTicketsOrKeys(tok, value)
		return nil
	case TicketsBodies:
		setTicketsOrKeys(tok, value)
		return nil
	default:
		return fmt.Errorf("unsupported type")
	}
}

func (tok TicketsOrKeys) IndexValue() (index uint, value any, err error) {
	switch tok.inner.(type) {
	case EpochKeys:
		return 1, tok.inner, nil
	case TicketsBodies:
		return 2, tok.inner, nil
	}
	return 0, nil, scale.ErrUnsupportedVaryingDataTypeValue
}

func (tok TicketsOrKeys) Value() (value any, err error) {
	_, value, err = tok.IndexValue()
	return
}

func (tok TicketsOrKeys) ValueAt(index uint) (value any, err error) {
	switch index {
	case 1:
		return EpochKeys{}, nil
	case 2:
		return TicketsBodies{}, nil
	}
	return nil, scale.ErrUnknownVaryingDataTypeValue
}

// OutputOrError is the output from Safrole protocol
type OutputOrError struct {
	inner any
}

type OutputOrErrorValues interface {
	OutputMarks | CustomErrorCode
}

type OutputMarks struct {
	EpochMark   *block.EpochMarker `json:"epoch_mark"`
	TicketsMark *TicketsMark       `json:"tickets_mark"`
}

func setOutputOrError[Value OutputOrErrorValues](oe *OutputOrError, value Value) {
	oe.inner = value
}

func (oe *OutputOrError) SetValue(value any) (err error) {
	switch value := value.(type) {
	case OutputMarks:
		setOutputOrError(oe, value)
		return nil
	case CustomErrorCode:
		setOutputOrError(oe, value)
		return nil
	default:
		return fmt.Errorf("unsupported type")
	}
}

func (oe OutputOrError) IndexValue() (index uint, value any, err error) {
	switch oe.inner.(type) {
	case OutputMarks:
		return 1, oe.inner, nil
	case CustomErrorCode:
		return 2, oe.inner, nil
	}
	return 0, nil, scale.ErrUnsupportedVaryingDataTypeValue
}

func (oe OutputOrError) Value() (value any, err error) {
	_, value, err = oe.IndexValue()
	return
}

func (oe OutputOrError) ValueAt(index uint) (value any, err error) {
	switch index {
	case 1:
		return OutputMarks{}, nil
	case 2:
		return CustomErrorCode(0), nil
	}
	return nil, scale.ErrUnknownVaryingDataTypeValue
}