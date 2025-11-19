package block

import (
	"testing"

	"github.com/eigerco/strawberry/internal/crypto/ed25519"

	"github.com/eigerco/strawberry/internal/common"
	"github.com/eigerco/strawberry/internal/testutils"
	"github.com/eigerco/strawberry/pkg/serialization/codec/jam"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_HeaderEncodeDecode(t *testing.T) {
	h := Header{
		ParentHash:     testutils.RandomHash(t),
		PriorStateRoot: testutils.RandomHash(t),
		ExtrinsicHash:  testutils.RandomHash(t),
		TimeSlotIndex:  123,
		EpochMarker: &EpochMarker{
			Entropy: testutils.RandomHash(t),
		},
		WinningTicketsMarker: &WinningTicketMarker{
			Ticket{
				Identifier: testutils.RandomBandersnatchOutputHash(t),
				EntryIndex: 111,
			}, Ticket{
				Identifier: testutils.RandomBandersnatchOutputHash(t),
				EntryIndex: 222,
			}},
		OffendersMarkers: []ed25519.PublicKey{
			testutils.RandomED25519PublicKey(t),
		},
		BlockAuthorIndex:   1,
		VRFSignature:       testutils.RandomBandersnatchSignature(t),
		BlockSealSignature: testutils.RandomBandersnatchSignature(t),
	}

	for i := 0; i < common.NumberOfValidators; i++ {
		h.EpochMarker.Keys[i].Bandersnatch = testutils.RandomBandersnatchPublicKey(t)
		h.EpochMarker.Keys[i].Ed25519 = testutils.RandomED25519PublicKey(t)
	}

	bb, err := jam.Marshal(h)
	require.NoError(t, err)

	h2 := Header{}
	err = jam.Unmarshal(bb, &h2)
	require.NoError(t, err)

	assert.Equal(t, h, h2)
}
