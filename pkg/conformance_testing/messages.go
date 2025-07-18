package conformance_testing

import (
	"fmt"
	"github.com/eigerco/strawberry/internal/block"
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/state/serialization/statekey"
	"github.com/eigerco/strawberry/pkg/serialization/codec/jam"
	"io"
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

type Message struct {
	// One of: PeerInfo, ImportBlock, SetState, GetState, State, StateRoot
	Choice MessageChoice
}

func (m *Message) UnmarshalJAM(reader io.Reader) error {
	msgType := make([]byte, 1)
	if _, err := reader.Read(msgType); err != nil {
		return err
	}
	switch msgType[0] {
	case peerInfoKind:
		innerMsg := PeerInfo{}
		if err := jam.NewDecoder(reader).Decode(&innerMsg); err != nil {
			return err
		}
		m.Choice = innerMsg
	case importBlockKind:
		innerMsg := ImportBlock{}
		if err := jam.NewDecoder(reader).Decode(&innerMsg); err != nil {
			return err
		}
		m.Choice = innerMsg
	case setStateKind:
		innerMsg := SetState{}
		if err := jam.NewDecoder(reader).Decode(&innerMsg); err != nil {
			return err
		}
		m.Choice = innerMsg
	case getStateKind:
		innerMsg := GetState{}
		if err := jam.NewDecoder(reader).Decode(&innerMsg); err != nil {
			return err
		}
		m.Choice = innerMsg
	case stateKind:
		innerMsg := State{}
		if err := jam.NewDecoder(reader).Decode(&innerMsg); err != nil {
			return err
		}
		m.Choice = innerMsg
	case stateRootKind:
		innerMsg := StateRoot{}
		if err := jam.NewDecoder(reader).Decode(&innerMsg); err != nil {
			return err
		}
		m.Choice = innerMsg
	default:
		return fmt.Errorf("unknown choice type")
	}
	return nil
}

func (m *Message) MarshalJAM() ([]byte, error) {
	var choiceByte byte
	if m.Choice == nil {
		return nil, fmt.Errorf("empty message choice")
	}
	switch m.Choice.(type) {
	case PeerInfo:
		choiceByte = peerInfoKind
	case ImportBlock:
		choiceByte = importBlockKind
	case SetState:
		choiceByte = setStateKind
	case GetState:
		choiceByte = getStateKind
	case State:
		choiceByte = stateKind
	case StateRoot:
		choiceByte = stateRootKind
	default:
		return nil, fmt.Errorf("unknown choice type")
	}
	bytes, err := jam.Marshal(m.Choice)
	if err != nil {
		return nil, err
	}
	bytes = append([]byte{choiceByte}, bytes...)
	return bytes, nil
}
