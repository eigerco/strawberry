package block

import (
	"crypto/ed25519"
	"crypto/rand"
	"github.com/eigerco/strawberry/internal/jamtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/pkg/serialization"
	"github.com/eigerco/strawberry/pkg/serialization/codec"
)

func Test_HeaderEncodeDecode(t *testing.T) {
	h := Header{
		ParentHash:     randomHash(t),
		PriorStateRoot: randomHash(t),
		ExtrinsicHash:  randomHash(t),
		TimeSlotIndex:  123,
		EpochMarker: &EpochMarker{
			Keys: [NumberOfValidators]crypto.BandersnatchPublicKey{
				randomPublicKey(t),
				randomPublicKey(t),
			},
			Entropy: randomHash(t),
		},
		WinningTicketsMarker: [jamtime.TimeslotsPerEpoch]*Ticket{{
			Identifier: randomHash(t),
			EntryIndex: 111,
		}, {
			Identifier: randomHash(t),
			EntryIndex: 222,
		}},
		Verdicts: []crypto.Hash{
			randomHash(t),
			randomHash(t),
		},
		OffendersMarkers: []crypto.Ed25519PublicKey{
			randomED25519PublicKey(t),
		},
		BlockAuthorIndex:   1,
		VRFSignature:       randomSignature(t),
		BlockSealSignature: randomSignature(t),
	}
	serializer := serialization.NewSerializer(&codec.JAMCodec{})
	bb, err := serializer.Encode(h)
	require.NoError(t, err)

	h2 := Header{}
	err = serializer.Decode(bb, &h2)
	require.NoError(t, err)

	assert.Equal(t, h, h2)
}

func randomHash(t *testing.T) crypto.Hash {
	hash := make([]byte, crypto.HashSize)
	_, err := rand.Read(hash)
	require.NoError(t, err)
	return crypto.Hash(hash)
}

func randomED25519PublicKey(t *testing.T) crypto.Ed25519PublicKey {
	hash := make([]byte, ed25519.PublicKeySize)
	_, err := rand.Read(hash)
	require.NoError(t, err)
	return hash
}
func randomPublicKey(t *testing.T) crypto.BandersnatchPublicKey {
	hash := make([]byte, crypto.BandersnatchSize)
	_, err := rand.Read(hash)
	require.NoError(t, err)
	return crypto.BandersnatchPublicKey(hash)
}

func randomSignature(t *testing.T) crypto.BandersnatchSignature {
	hash := make([]byte, 96)
	_, err := rand.Read(hash)
	require.NoError(t, err)
	return crypto.BandersnatchSignature(hash)
}
