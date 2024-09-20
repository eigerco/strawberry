package block

import (
	"testing"

	"github.com/eigerco/strawberry/internal/jamtime"
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
			Keys: [NumberOfValidators]crypto.BandersnatchPublicKey{
				testutils.RandomBandersnatchPublicKey(t),
				testutils.RandomBandersnatchPublicKey(t),
			},
			Entropy: testutils.RandomHash(t),
		},
		WinningTicketsMarker: &[jamtime.TimeslotsPerEpoch]Ticket{{
			Identifier: testutils.RandomHash(t),
			EntryIndex: 111,
		}, {
			Identifier: testutils.RandomHash(t),
			EntryIndex: 222,
		}},
		OffendersMarkers: []crypto.Ed25519PublicKey{
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
