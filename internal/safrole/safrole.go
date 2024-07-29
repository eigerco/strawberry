package safrole

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/ChainSafe/gossamer/pkg/scale"
)

const (
	validatorsCount = 6  // 1023 on full test vectors
	epochLength     = 12 // 600 on full test vectors

	// Custom error codes as defined here https://github.com/w3f/jamtestvectors/blob/master/safrole/safrole.asn#L30

	BadSlot          CustomErrorCode = 0 // Timeslot value must be strictly monotonic.
	UnexpectedTicket CustomErrorCode = 1 // Received a ticket while in epoch's tail.
	BadTicketOrder   CustomErrorCode = 2 // Tickets must be sorted.
	BadTicketProof   CustomErrorCode = 3 // Invalid ticket ring proof.
	BadTicketAttempt CustomErrorCode = 4 // Invalid ticket attempt value.
	Reserved         CustomErrorCode = 5 // Reserved
	DuplicateTicket  CustomErrorCode = 6 // Found a ticket duplicate.
)

var errorCodeMessages = map[CustomErrorCode]string{
	BadSlot:          "bad_slot",
	UnexpectedTicket: "unexpected_ticket",
	BadTicketOrder:   "bad_ticket_order",
	BadTicketProof:   "bad_ticket_proof",
	BadTicketAttempt: "bad_ticket_attempt",
	Reserved:         "reserved",
	DuplicateTicket:  "duplicate_ticket",
}

type OpaqueHash [32]byte
type Ed25519Key [32]uint8
type BlsKey [144]uint8
type BandersnatchKey [32]uint8
type MetadataKey [128]uint8
type GammaZ [144]uint8

type EpochKeys [epochLength]BandersnatchKey
type TicketsBodies [epochLength]TicketBody

type Safrole struct {
	Input     Input         `json:"input"`
	PreState  State         `json:"pre_state"`
	Output    OutputOrError `json:"output"`
	PostState State         `json:"post_state"`
}

type Input struct {
	Slot      uint32           `json:"slot"`
	Entropy   OpaqueHash       `json:"entropy"`
	Extrinsic []TicketEnvelope `json:"extrinsic"`
}

type ValidatorData struct {
	Bandersnatch BandersnatchKey `json:"bandersnatch"`
	Ed25519      Ed25519Key      `json:"ed25519"`
	Bls          BlsKey          `json:"bls"`
	Metadata     MetadataKey     `json:"metadata"`
}
type ValidatorsData [validatorsCount]ValidatorData

type EpochMark struct {
	Entropy    OpaqueHash
	Validators [validatorsCount]BandersnatchKey
}

type TicketsMark [epochLength]TicketBody

type OutputMarks struct {
	EpochMark   *EpochMark   `json:"epoch_mark"`
	TicketsMark *TicketsMark `json:"tickets_mark"`
}

type CustomErrorCode int

type State struct {
	Tau    uint32         `json:"tau"`
	Eta    [4]OpaqueHash  `json:"eta"`
	Lambda ValidatorsData `json:"lambda"`
	Kappa  ValidatorsData `json:"kappa"`
	GammaK ValidatorsData `json:"gamma_k"`
	Iota   ValidatorsData `json:"iota"`
	GammaA []TicketBody   `json:"gamma_a"`
	GammaS TicketsOrKeys  `json:"gamma_s"`
	GammaZ GammaZ         `json:"gamma_z"`
}

func (h OpaqueHash) MarshalJSON() ([]byte, error) {
	return json.Marshal(fmt.Sprintf("0x%s", hex.EncodeToString(h[:])))
}

func (k Ed25519Key) MarshalJSON() ([]byte, error) {
	return json.Marshal(fmt.Sprintf("0x%s", hex.EncodeToString(k[:])))
}

func (k BlsKey) MarshalJSON() ([]byte, error) {
	return json.Marshal(fmt.Sprintf("0x%s", hex.EncodeToString(k[:])))
}

func (k GammaZ) MarshalJSON() ([]byte, error) {
	return json.Marshal(fmt.Sprintf("0x%s", hex.EncodeToString(k[:])))
}

func (k BandersnatchKey) MarshalJSON() ([]byte, error) {
	return json.Marshal(fmt.Sprintf("0x%s", hex.EncodeToString(k[:])))
}

func (k MetadataKey) MarshalJSON() ([]byte, error) {
	return json.Marshal(fmt.Sprintf("0x%s", hex.EncodeToString(k[:])))
}

type TicketEnvelope struct {
	Attempt   uint8
	Signature [784]uint8
}

type TicketBody struct {
	ID      OpaqueHash
	Attempt uint8
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

func (tok TicketsOrKeys) MarshalJSON() ([]byte, error) {
	value, err := tok.Value()
	if err != nil {
		return nil, err
	}

	switch v := value.(type) {
	case EpochKeys:
		return json.Marshal(map[string]interface{}{
			"keys": v,
		})
	case TicketsBodies:
		return json.Marshal(map[string]interface{}{
			"tickets": v,
		})
	default:
		return nil, fmt.Errorf("unexpected type in TicketsOrKeys: %T", value)
	}
}

// OutputOrError is enum
type OutputOrError struct {
	inner any
}

type OutputOrErrorValues interface {
	OutputMarks | CustomErrorCode
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
	case 0:
		return OutputMarks{}, nil
	case 1:
		return CustomErrorCode(0), nil
	}
	return nil, scale.ErrUnknownVaryingDataTypeValue
}

func (oe OutputOrError) MarshalJSON() ([]byte, error) {
	value, err := oe.Value()
	if err != nil {
		return nil, err
	}

	switch v := value.(type) {
	case OutputMarks:
		return json.Marshal(map[string]interface{}{
			"ok": v,
		})
	case CustomErrorCode:
		message, ok := errorCodeMessages[v]
		if !ok {
			return nil, fmt.Errorf("unknown custom error code: %d", v)
		}
		return json.Marshal(map[string]interface{}{
			"err": message,
		})
	default:
		return nil, fmt.Errorf("unexpected type in OutputOrError: %T", value)
	}
}
