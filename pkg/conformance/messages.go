package conformance

import (
	"encoding/hex"
	"fmt"

	"github.com/eigerco/strawberry/internal/block"
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/state/serialization/statekey"
	"github.com/eigerco/strawberry/pkg/serialization/codec/jam"
)

const (
	peerInfoKind    = 0
	initializeKind  = 1
	stateRootKind   = 2
	importBlockKind = 3
	getStateKind    = 4
	stateKind       = 5
	errorKind       = 255
)

type MessageChoice interface {
	isMessageChoice()
}

type Version struct {
	Major uint8
	Minor uint8
	Patch uint8
}

func (v Version) String() string {
	return fmt.Sprintf("%d.%d.%d", v.Major, v.Minor, v.Patch)
}

type PeerInfo struct {
	FuzzVersion  uint8
	FuzzFeatures Features
	JamVersion   Version
	AppVersion   Version
	Name         []byte
}

func (p PeerInfo) isMessageChoice() {}

type Initialize struct {
	Header   block.Header
	State    State
	Ancestry Ancestry
}

func (s Initialize) isMessageChoice() {}

type StateRoot struct {
	StateRootHash crypto.Hash
}

func (s StateRoot) isMessageChoice() {}

func (s StateRoot) String() string {
	return "0x" + hex.EncodeToString(s.StateRootHash[:])
}

type ImportBlock struct {
	Block block.Block
}

func (i ImportBlock) isMessageChoice() {}

type GetState struct {
	HeaderHash crypto.Hash
}

func (g GetState) isMessageChoice() {}

type State struct {
	StateItems []statekey.KeyValue
}

func (s State) isMessageChoice() {}

type Error struct {
	Message []byte
}

func (e Error) isMessageChoice() {}

func (e Error) String() string {
	return string(e.Message)
}

type AncestryItem struct {
	Slot uint32
	Hash crypto.Hash
}

type Ancestry struct {
	Items []AncestryItem // Up to 24 items
}

// NewMessage creates a new message with the inner choice
func NewMessage(choice MessageChoice) *Message {
	return &Message{
		choice: choice,
	}
}

type Message struct {
	// One of: PeerInfo, Initialize, StateRoot, ImportBlock, GetState, State, Error
	choice MessageChoice
}

func (m *Message) IndexValue() (index uint, value any, err error) {
	switch m.choice.(type) {
	case PeerInfo:
		return peerInfoKind, m.choice, nil
	case Initialize:
		return initializeKind, m.choice, nil
	case StateRoot:
		return stateRootKind, m.choice, nil
	case ImportBlock:
		return importBlockKind, m.choice, nil
	case GetState:
		return getStateKind, m.choice, nil
	case State:
		return stateKind, m.choice, nil
	case Error:
		return errorKind, m.choice, nil
	default:
		return 0, nil, jam.ErrUnsupportedEnumTypeValue
	}
}

func (m *Message) ValueAt(index uint) (value any, err error) {
	switch index {
	case peerInfoKind:
		return PeerInfo{}, nil
	case initializeKind:
		return Initialize{}, nil
	case stateRootKind:
		return StateRoot{}, nil
	case importBlockKind:
		return ImportBlock{}, nil
	case getStateKind:
		return GetState{}, nil
	case stateKind:
		return State{}, nil
	case errorKind:
		return Error{}, nil
	}
	return nil, jam.ErrUnsupportedEnumTypeValue
}

func (m *Message) SetValue(value any) error {
	switch value := value.(type) {
	case PeerInfo:
		m.choice = value
	case Initialize:
		m.choice = value
	case StateRoot:
		m.choice = value
	case ImportBlock:
		m.choice = value
	case GetState:
		m.choice = value
	case State:
		m.choice = value
	case Error:
		m.choice = value
	default:
		return fmt.Errorf(jam.ErrUnsupportedType, value)
	}
	return nil
}

func (m *Message) Get() MessageChoice {
	return m.choice
}
