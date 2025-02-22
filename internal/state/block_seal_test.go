package state

import (
	"testing"

	"github.com/eigerco/strawberry/internal/block"
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/crypto/bandersnatch"
	"github.com/eigerco/strawberry/internal/jamtime"
	"github.com/eigerco/strawberry/internal/safrole"
	"github.com/eigerco/strawberry/internal/testutils"
	"github.com/eigerco/strawberry/internal/validator"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/exp/rand"
)

func TestSealVerifyBlockTicket(t *testing.T) {
	entropy := testutils.RandomHash(t)
	ticketBodies := randomTicketBodies(t, entropy)

	randomTimeslot := testutils.RandomUint32() % jamtime.TimeslotsPerEpoch
	t.Logf("random timeslot: %d", randomTimeslot)

	// Replace one of the keys in the accumulator with our public key. This
	// should later be selected as the winning key.
	privateKey := testutils.RandomBandersnatchPrivateKey(t)
	publicKey, err := bandersnatch.Public(privateKey)
	require.NoError(t, err)
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

	currentValidators := safrole.ValidatorsData{}
	currentValidators[1] = &crypto.ValidatorKey{
		Bandersnatch: publicKey,
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
			CurrentValidators: currentValidators,
		},
	}

	err = SealBlock(header, state, privateKey)
	require.NoError(t, err)
	assert.NotEmpty(t, header.BlockSealSignature)
	assert.NotEmpty(t, header.VRFSignature)

	ok, err := VerifyBlockSeal(header, state)
	require.NoError(t, err)
	require.True(t, ok)
}

func TestSealVerifyBlockFallback(t *testing.T) {
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

	ok, err := VerifyBlockSeal(header, state)
	require.NoError(t, err)
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
