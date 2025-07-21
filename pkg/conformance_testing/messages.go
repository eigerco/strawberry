package conformance_testing

import (
	"fmt"
	"github.com/eigerco/strawberry/internal/block"
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/state/serialization/statekey"
	"github.com/eigerco/strawberry/pkg/serialization/codec/jam"
)

const (
	peerInfoKind    = 0
	importBlockKind = 1
	setStateKind    = 2
	getStateKind    = 3
	stateKind       = 4
	stateRootKind   = 5
)

type MessageChoice interface {
	isMessageChoice()
}

type Version struct {
	Major int // 0..255
	Minor int // 0..255
	Patch int // 0..255
}

func (v Version) String() string {
	return fmt.Sprintf("%d.%d.%d", v.Major, v.Minor, v.Patch)
}

type PeerInfo struct {
	Name       []byte
	AppVersion Version
	JamVersion Version
}

func (p PeerInfo) isMessageChoice() {}

type SetState struct {
	Header block.Header
	State  State
}

func (s SetState) isMessageChoice() {}

type StateRoot struct {
	StateRootHash crypto.Hash
}

func (s StateRoot) isMessageChoice() {}

type KeyValue struct {
	Key   statekey.StateKey
	Value []byte
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
	StateItems []KeyValue
}

func (s State) isMessageChoice() {}

// NewMessage creates a new message with the inner choice
func NewMessage(choice MessageChoice) *Message {
	return &Message{
		choice: choice,
	}
}

type Message struct {
	// One of: PeerInfo, ImportBlock, SetState, GetState, State, StateRoot
	choice MessageChoice
}

func (m *Message) IndexValue() (index uint, value any, err error) {
	switch m.choice.(type) {
	case PeerInfo:
		return peerInfoKind, m.choice, nil
	case ImportBlock:
		return importBlockKind, m.choice, nil
	case SetState:
		return setStateKind, m.choice, nil
	case GetState:
		return getStateKind, m.choice, nil
	case State:
		return stateKind, m.choice, nil
	case StateRoot:
		return stateRootKind, m.choice, nil
	default:
		return 0, nil, jam.ErrUnsupportedEnumTypeValue
	}
}

func (m *Message) ValueAt(index uint) (value any, err error) {
	switch index {
	case peerInfoKind:
		return PeerInfo{}, nil
	case importBlockKind:
		return ImportBlock{}, nil
	case setStateKind:
		return SetState{}, nil
	case getStateKind:
		return GetState{}, nil
	case stateKind:
		return State{}, nil
	case stateRootKind:
		return StateRoot{}, nil
	}
	return nil, jam.ErrUnsupportedEnumTypeValue
}

func (m *Message) SetValue(value any) error {
	switch value := value.(type) {
	case PeerInfo:
		m.choice = value
	case ImportBlock:
		m.choice = value
	case SetState:
		m.choice = value
	case GetState:
		m.choice = value
	case State:
		m.choice = value
	case StateRoot:
		m.choice = value
	default:
		return fmt.Errorf(jam.ErrUnsupportedType, value)
	}
	return nil
}

func (m *Message) Get() MessageChoice {
	return m.choice
}
