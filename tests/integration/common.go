package integration

import (
	"github.com/eigerco/strawberry/internal/block"
	"github.com/eigerco/strawberry/internal/crypto"
)

type KeyValue struct {
	Key   [31]byte `json:"key"`
	Value []byte   `json:"value"`
}

type RawState struct {
	StateRoot crypto.Hash
	KeyValues []KeyValue
}

type Trace struct {
	PreState  RawState
	Block     block.Block
	PostState RawState
}
