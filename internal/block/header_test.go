package block

import (
	"crypto/rand"
	"testing"

	"github.com/ChainSafe/gossamer/pkg/scale"
	"github.com/eigerco/strawberry/internal/time"
	"github.com/stretchr/testify/assert"

	"github.com/eigerco/strawberry/internal/crypto"
)

func Test_HeaderMarshalUnmarshal(t *testing.T) {
	h := Header{
		ParentHash:     randomHash(),
		PriorStateRoot: randomHash(),
		ExtrinsicHash:  randomHash(),
		TimeSlotIndex:  123,
		EpochMarker: &EpochMarker{
			Keys: [NumberOfValidators]crypto.BandersnatchPublicKey{
				randomPublicKey(),
				randomPublicKey(),
			},
			Entropy: randomHash(),
		},
		WinningTicketsMarker: [time.TimeslotsPerEpoch]*Ticket{{
			Identifier: randomHash(),
			EntryIndex: 111,
		}, {
			Identifier: randomHash(),
			EntryIndex: 222,
		}},
		JudgementsMarkers: []crypto.Hash{
			randomHash(),
			randomHash(),
		},
		PublicKeyIndex:     1,
		VRFSignature:       randomSignature(),
		BlockSealSignature: randomSignature(),
	}
	bb, err := scale.Marshal(h)
	if err != nil {
		t.Fatal(err)
	}

	h2 := Header{}
	err = scale.Unmarshal(bb, &h2)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, h, h2)
}

func randomHash() crypto.Hash {
	hash := make([]byte, crypto.HashSize)
	_, err := rand.Read(hash)
	if err != nil {
		panic(err)
	}
	return crypto.Hash(hash)
}
func randomPublicKey() crypto.BandersnatchPublicKey {
	hash := make([]byte, crypto.BandersnatchSize)
	_, err := rand.Read(hash)
	if err != nil {
		panic(err)
	}
	return crypto.BandersnatchPublicKey(hash)
}
func randomSignature() crypto.BandersnatchSignature {
	hash := make([]byte, 96)
	_, err := rand.Read(hash)
	if err != nil {
		panic(err)
	}
	return crypto.BandersnatchSignature(hash)
}
