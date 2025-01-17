package state

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/eigerco/strawberry/internal/block"
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/crypto/bandersnatch"
	"github.com/eigerco/strawberry/internal/jamtime"
	"github.com/eigerco/strawberry/internal/safrole"
	"github.com/eigerco/strawberry/internal/testutils"
	"github.com/eigerco/strawberry/internal/validator"
	"github.com/eigerco/strawberry/pkg/serialization/codec/jam"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/exp/rand"
)

func TestSealBlockTicket(t *testing.T) {
	entropy := testutils.RandomHash(t)
	ticketBodies := randomTicketBodies(t, entropy)

	randomTimeslot := testutils.RandomUint32() % jamtime.TimeslotsPerEpoch
	t.Logf("random timeslot: %d", randomTimeslot)

	// Replace one of the keys in the accumulator with our public key. This
	// should later be selected as the winning key.
	privateKey := testutils.RandomBandersnatchPrivateKey(t)
	ticket := createTicket(t, privateKey, entropy, 0)
	ticketBodies[randomTimeslot] = ticket

	ticketAccumulator := safrole.TicketAccumulator{}
	ticketAccumulator.Set(ticketBodies)

	header := &block.Header{
		ParentHash:     testutils.RandomHash(t),
		PriorStateRoot: testutils.RandomHash(t),
		ExtrinsicHash:  testutils.RandomHash(t),
		TimeSlotIndex:  jamtime.Timeslot(randomTimeslot),
	}

	state := &State{
		EntropyPool: [4]crypto.Hash{
			testutils.RandomHash(t),
			testutils.RandomHash(t),
			testutils.RandomHash(t),
			entropy,
		},
		ValidatorState: validator.ValidatorState{
			SafroleState: safrole.State{
				SealingKeySeries: ticketAccumulator,
			},
		},
	}

	err := SealBlock(header, state, privateKey)
	require.NoError(t, err)
	assert.NotEmpty(t, header.BlockSealSignature)
	assert.NotEmpty(t, header.VRFSignature)

	expectedTicketID, err := bandersnatch.OutputHash(header.BlockSealSignature)
	require.NoError(t, err)
	assert.Equal(t, expectedTicketID, ticket.Identifier)
}

func TestSealBlockFallback(t *testing.T) {
	privateKey := testutils.RandomBandersnatchPrivateKey(t)
	publicKey, err := bandersnatch.Public(privateKey)
	require.NoError(t, err)

	var epochKeys = testutils.RandomEpochKeys(t)

	randomTimeslot := testutils.RandomUint32() % jamtime.TimeslotsPerEpoch
	t.Logf("random timeslot: %d", randomTimeslot)

	// Replace one of the keys in the accumulator with our public key. This
	// should later be selected as the winning key.
	epochKeys[randomTimeslot] = publicKey

	ticketAccumulator := safrole.TicketAccumulator{}
	ticketAccumulator.Set(epochKeys)

	header := &block.Header{
		ParentHash:     testutils.RandomHash(t),
		PriorStateRoot: testutils.RandomHash(t),
		ExtrinsicHash:  testutils.RandomHash(t),
		TimeSlotIndex:  jamtime.Timeslot(randomTimeslot),
	}
	unsealedHeader, err := encodeUnsealedHeader(*header)
	require.NoError(t, err)

	entropy := testutils.RandomHash(t)
	state := &State{
		EntropyPool: [4]crypto.Hash{
			testutils.RandomHash(t),
			testutils.RandomHash(t),
			testutils.RandomHash(t),
			entropy,
		},
		ValidatorState: validator.ValidatorState{
			SafroleState: safrole.State{
				SealingKeySeries: ticketAccumulator,
			},
		},
	}

	err = SealBlock(header, state, privateKey)
	require.NoError(t, err)
	assert.NotEmpty(t, header.BlockSealSignature)
	assert.NotEmpty(t, header.VRFSignature)

	// Sanity check that our private key did sign.
	vrfInput := buildTicketFallbackContext(entropy)
	require.NoError(t, err)
	ok, _ := bandersnatch.Verify(publicKey, vrfInput, unsealedHeader, header.BlockSealSignature)
	require.True(t, ok)

}

func TestSealBlockInvalidAuthor(t *testing.T) {
	entropy := testutils.RandomHash(t)
	ticketBodies := randomTicketBodies(t, entropy)

	ticketAccumulator := safrole.TicketAccumulator{}
	ticketAccumulator.Set(ticketBodies)

	header := &block.Header{
		ParentHash:     testutils.RandomHash(t),
		PriorStateRoot: testutils.RandomHash(t),
		ExtrinsicHash:  testutils.RandomHash(t),
		TimeSlotIndex:  testutils.RandomTimeslot(),
	}

	state := &State{
		EntropyPool: [4]crypto.Hash{
			testutils.RandomHash(t),
			testutils.RandomHash(t),
			testutils.RandomHash(t),
			entropy,
		},
		ValidatorState: validator.ValidatorState{
			SafroleState: safrole.State{
				SealingKeySeries: ticketAccumulator,
			},
		},
	}

	privateKey := testutils.RandomBandersnatchPrivateKey(t)
	err := SealBlock(header, state, privateKey)
	require.ErrorIs(t, err, ErrBlockSealInvalidAuthor)
}

func TestBlockSealCommunityVectors(t *testing.T) {
	testFiles := []string{
		"testdata/0-0.json",
		"testdata/1-0.json",
	}

	for _, tf := range testFiles {
		t.Run(filepath.Base(tf), func(t *testing.T) {
			file, err := os.ReadFile(tf)
			require.NoError(t, err)

			var tv blockSealTestData
			err = json.Unmarshal(file, &tv)
			require.NoError(t, err)

			var header block.Header
			headerBytes := testutils.MustFromHex(t, tv.HeaderBytes)
			err = jam.Unmarshal(headerBytes, &header)
			require.NoError(t, err)

			privateKey := crypto.BandersnatchPrivateKey(testutils.MustFromHex(t, tv.BandersnatchPriv))
			entropy := crypto.Hash(testutils.MustFromHex(t, tv.Eta3))

			var ticketOrKey TicketOrKey
			if tv.T == 1 {
				ticketOrKey = block.Ticket{
					Identifier: crypto.BandersnatchOutputHash(testutils.MustFromHex(t, tv.TicketID)),
					EntryIndex: tv.Attempt,
				}
			} else { // Fallback case.
				ticketOrKey = crypto.BandersnatchPublicKey(testutils.MustFromHex(t, tv.BandersnatchPub))
			}

			sealSignature, vrfsSignature, err := SignBlock(header, ticketOrKey, privateKey, entropy)
			require.NoError(t, err)

			require.Equal(t, hex.EncodeToString(sealSignature[:]), tv.Hs)
			require.Equal(t, hex.EncodeToString(vrfsSignature[:]), tv.Hv)
		})
	}
}

type blockSealTestData struct {
	BandersnatchPub  string `json:"bandersnatch_pub"`
	BandersnatchPriv string `json:"bandersnatch_priv"`
	TicketID         string `json:"ticket_id"`
	Attempt          uint8  `json:"attempt"`
	CForHs           string `json:"c_for_H_s"`
	MForHs           string `json:"m_for_H_s"`
	Hs               string `json:"H_s"`
	CForHv           string `json:"c_for_H_v"`
	MForHv           string `json:"m_for_H_v"`
	Hv               string `json:"H_v"`
	Eta3             string `json:"eta3"`
	T                int    `json:"T"`
	HeaderBytes      string `json:"header_bytes"`
}

func createTicket(t *testing.T, privateKey crypto.BandersnatchPrivateKey, entropy crypto.Hash, attempt uint8) block.Ticket {
	vrfInput := buildTicketSealContext(entropy, attempt)
	signature, err := bandersnatch.Sign(privateKey, vrfInput, []byte{})
	require.NoError(t, err)

	outputHash, err := bandersnatch.OutputHash(signature)
	require.NoError(t, err)

	return block.Ticket{
		Identifier: outputHash,
		EntryIndex: attempt,
	}
}

func randomTicketBodies(t *testing.T, entropy crypto.Hash) safrole.TicketsBodies {
	var ticketsBodies safrole.TicketsBodies

	for i := 0; i < jamtime.TimeslotsPerEpoch; i++ {
		privateKey := testutils.RandomBandersnatchPrivateKey(t)
		attempt := uint8(rand.Intn(256))
		ticketsBodies[i] = createTicket(t, privateKey, entropy, attempt)
	}

	return ticketsBodies
}
