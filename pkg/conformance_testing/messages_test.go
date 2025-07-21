package conformance_testing

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
			Name: []byte("test 123"),
			AppVersion: Version{
				Major: 1,
				Minor: 2,
				Patch: 3,
			},
			JamVersion: Version{
				Major: 4,
				Minor: 5,
				Patch: 6,
			},
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
		name: "set state",
		msg: NewMessage(SetState{
			Header: block.Header{
				ParentHash: testutils.RandomHash(t),
			},
			State: State{StateItems: []KeyValue{{
				Key:   statekey.NewBasic(1),
				Value: testutils.RandomBytes(t, 100),
			}}},
		}),
	}, {
		name: "get state",
		msg: NewMessage(GetState{
			HeaderHash: testutils.RandomHash(t),
		}),
	}, {
		name: "state",
		msg: NewMessage(State{StateItems: []KeyValue{{
			Key:   statekey.NewBasic(2),
			Value: testutils.RandomBytes(t, 50),
		}}}),
	}, {
		name: "state root",
		msg: NewMessage(StateRoot{
			StateRootHash: testutils.RandomHash(t),
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
