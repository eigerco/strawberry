package state

import (
	"testing"

	"github.com/eigerco/strawberry/internal/block"
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/safrole"
	"github.com/eigerco/strawberry/internal/testutils"
	"github.com/eigerco/strawberry/internal/validator"
	"github.com/eigerco/strawberry/pkg/serialization"
	"github.com/eigerco/strawberry/pkg/serialization/codec"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEncodeUnsealedHeader(t *testing.T) {
	header := block.Header{
		ParentHash:         testutils.RandomHash(t),
		PriorStateRoot:     testutils.RandomHash(t),
		ExtrinsicHash:      testutils.RandomHash(t),
		TimeSlotIndex:      123,
		VRFSignature:       testutils.RandomBandersnatchSignature(t),
		BlockSealSignature: testutils.RandomBandersnatchSignature(t),
	}
	serializer := serialization.NewSerializer(&codec.JAMCodec{})
	encoded, err := encodeUnsealedHeader(header)
	require.NoError(t, err)
	require.NotNil(t, encoded)
	decoded := &block.Header{}
	err = serializer.Decode(encoded, decoded)
	require.NoError(t, err)
	assert.Empty(t, decoded.BlockSealSignature)
	// Check that the rest of the header is the same
	header.BlockSealSignature = crypto.BandersnatchSignature{}
	assert.Equal(t, header, *decoded)
}
func TestBuildSealContextWithKey(t *testing.T) {
	hash := testutils.RandomHash(t)
	header := &block.Header{
		TimeSlotIndex: 123,
	}
	toks := safrole.TicketsOrKeys{}
	var epochKeys crypto.EpochKeys
	epochKeys[0] = testutils.RandomBandersnatchPublicKey(t)
	err := toks.SetValue(epochKeys)
	require.NoError(t, err)
	state := &State{
		EntropyPool: [4]crypto.Hash{
			testutils.RandomHash(t),
			testutils.RandomHash(t),
			testutils.RandomHash(t),
			hash,
		},
	}
	validatorState := validator.SetupValidatorState(t)
	state.ValidatorState = *validatorState
	context, err := buildSealContext(header, state)
	require.NoError(t, err)
	fallbackSealContext := append([]byte(fallbackSealContext), hash[:]...)
	assert.Equal(t, fallbackSealContext, context)
	assert.Equal(t, byte(0), T)
}

func TestBuildSealContextWithTicket(t *testing.T) {
	hash := testutils.RandomHash(t)
	header := &block.Header{
		TimeSlotIndex: 123,
	}
	toks := safrole.TicketsOrKeys{}
	var tickets = safrole.TicketsBodies{}
	tickets[0] = validator.RandomTicket(t)
	err := toks.SetValue(tickets)
	require.NoError(t, err)
	state := &State{
		EntropyPool: [4]crypto.Hash{
			testutils.RandomHash(t),
			testutils.RandomHash(t),
			testutils.RandomHash(t),
			hash,
		},
	}
	validatorState := validator.SetupValidatorState(t)
	validatorState.SafroleState.SealingKeySeries = toks
	state.ValidatorState = *validatorState

	context, err := buildSealContext(header, state)
	require.NoError(t, err)
	expected := ticketSealContext + string(hash[:]) + string(rune(0))
	assert.Equal(t, []byte(expected), context)
	assert.Equal(t, byte(1), T)
}

func TestSealBlockAndUpdateEntropy(t *testing.T) {
	privateKey := testutils.RandomBandersnatchPrivateKey(t)
	sealingKeySeries := safrole.TicketsOrKeys{}
	var epochKeys = testutils.RandomEpochKeys(t)
	err := sealingKeySeries.SetValue(epochKeys)
	require.NoError(t, err)
	header := &block.Header{
		ParentHash:     testutils.RandomHash(t),
		PriorStateRoot: testutils.RandomHash(t),
		ExtrinsicHash:  testutils.RandomHash(t),
		TimeSlotIndex:  123,
	}
	state := &State{
		EntropyPool: [4]crypto.Hash{
			testutils.RandomHash(t),
			testutils.RandomHash(t),
			testutils.RandomHash(t),
			testutils.RandomHash(t),
		},
		ValidatorState: validator.ValidatorState{
			SafroleState: safrole.State{
				SealingKeySeries: sealingKeySeries,
			},
		},
	}

	err = sealBlockAndUpdateEntropy(header, state, privateKey)
	require.NoError(t, err)
	assert.NotEmpty(t, header.BlockSealSignature)
	assert.NotEmpty(t, header.VRFSignature)
	assert.NotEqual(t, state.EntropyPool[0], [32]byte{})
}
func TestRotateEntropyPool(t *testing.T) {
	initialEntropyPool := [4]crypto.Hash{
		testutils.RandomHash(t),
		testutils.RandomHash(t),
		testutils.RandomHash(t),
		testutils.RandomHash(t),
	}
	result := RotateEntropyPool(initialEntropyPool)
	assert.Equal(t, initialEntropyPool[2], result[3])
	assert.Equal(t, initialEntropyPool[1], result[2])
	assert.Equal(t, initialEntropyPool[0], result[1])
}
