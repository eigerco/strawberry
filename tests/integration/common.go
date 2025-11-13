package integration

import (
	"github.com/eigerco/strawberry/internal/block"
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/state/serialization/statekey"
)

type StateWithRoot struct {
	StateRoot crypto.Hash
	KeyValues []statekey.KeyValue
}

type Trace struct {
	PreState  StateWithRoot
	Block     block.Block
	PostState StateWithRoot
}

type Genesis struct {
	Header block.Header
	State  StateWithRoot
}
