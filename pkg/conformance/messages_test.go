package conformance

import (
	"testing"

	"github.com/eigerco/strawberry/internal/block"
	"github.com/eigerco/strawberry/internal/state/serialization/statekey"
	"github.com/eigerco/strawberry/internal/testutils"
	"github.com/eigerco/strawberry/pkg/serialization/codec/jam"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMessageEncoding(t *testing.T) {
	tests := []struct {
		name string
		msg  *Message
	}{{
		name: "peer info",
		msg: NewMessage(PeerInfo{
			FuzzVersion:  1,
			FuzzFeatures: 2,
			JamVersion: Version{
				Major: 4,
				Minor: 5,
				Patch: 6,
			},
			AppVersion: Version{
				Major: 1,
				Minor: 2,
				Patch: 3,
			},
			Name: []byte("test 123"),
		}),
	}, {
		name: "import block",
		msg: NewMessage(ImportBlock{
			Block: block.Block{
				Header: block.Header{
					ParentHash: testutils.RandomHash(t),
				},
				Extrinsic: block.Extrinsic{
					EA: block.AssurancesExtrinsic{{
						Anchor: testutils.RandomHash(t),
					}},
				},
			},
		}),
	}, {
		name: "initialize",
		msg: NewMessage(Initialize{
			Header: block.Header{
				ParentHash: testutils.RandomHash(t),
			},
			State: State{StateItems: []statekey.KeyValue{{
				Key:   statekey.NewBasic(1),
				Value: testutils.RandomBytes(t, 100),
			}}},
		}),
	}, {
		name: "initialize with ancestry",
		msg: NewMessage(Initialize{
			Header: block.Header{
				ParentHash: testutils.RandomHash(t),
			},
			State: State{StateItems: []statekey.KeyValue{{
				Key:   statekey.NewBasic(3),
				Value: testutils.RandomBytes(t, 64),
			}}},
			Ancestry: Ancestry{Items: []AncestryItem{{
				Slot: 42,
				Hash: testutils.RandomHash(t),
			}, {
				Slot: 43,
				Hash: testutils.RandomHash(t),
			}}},
		}),
	}, {
		name: "get state",
		msg: NewMessage(GetState{
			HeaderHash: testutils.RandomHash(t),
		}),
	}, {
		name: "state",
		msg: NewMessage(State{StateItems: []statekey.KeyValue{{
			Key:   statekey.NewBasic(2),
			Value: testutils.RandomBytes(t, 50),
		}}}),
	}, {
		name: "state root",
		msg: NewMessage(StateRoot{
			StateRootHash: testutils.RandomHash(t),
		}),
	}, {
		name: "error",
		msg: NewMessage(Error{
			Message: []byte("just a test error"),
		}),
	}}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			bb, err := jam.Marshal(test.msg)
			require.NoError(t, err)

			decodedMsg := &Message{}
			err = jam.Unmarshal(bb, decodedMsg)
			require.NoError(t, err)

			assert.Equal(t, test.msg, decodedMsg)
		})
	}
}
