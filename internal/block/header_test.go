package block

import (
	"crypto/ed25519"
	"testing"

	"github.com/eigerco/strawberry/internal/common"

	"github.com/eigerco/strawberry/internal/testutils"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/pkg/serialization"
	"github.com/eigerco/strawberry/pkg/serialization/codec"
)

func Test_HeaderEncodeDecode(t *testing.T) {
	h := Header{
		ParentHash:     testutils.RandomHash(t),
		PriorStateRoot: testutils.RandomHash(t),
		ExtrinsicHash:  testutils.RandomHash(t),
		TimeSlotIndex:  123,
		EpochMarker: &EpochMarker{
			Keys: [common.NumberOfValidators]crypto.BandersnatchPublicKey{
				testutils.RandomBandersnatchPublicKey(t),
				testutils.RandomBandersnatchPublicKey(t),
			},
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
	serializer := serialization.NewSerializer(&codec.JAMCodec{})
	bb, err := serializer.Encode(h)
	require.NoError(t, err)

	h2 := Header{}
	err = serializer.Decode(bb, &h2)
	require.NoError(t, err)

	assert.Equal(t, h, h2)
}
