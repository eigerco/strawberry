package state

import (
	"testing"

	"github.com/eigerco/strawberry/internal/block"
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/crypto/bandersnatch"
	"github.com/eigerco/strawberry/internal/safrole"
	"github.com/eigerco/strawberry/internal/testutils"
	"github.com/eigerco/strawberry/internal/validator"
	"github.com/stretchr/testify/require"
)

func TestCreateVerifyTicketProof(t *testing.T) {
	entropy := testutils.RandomHash(t)
	privateKey := testutils.RandomBandersnatchPrivateKey(t)

	currentValidators := safrole.ValidatorsData{}
	for i := range currentValidators {
		currentValidators[i] = &crypto.ValidatorKey{
			Bandersnatch: testutils.RandomBandersnatchPublicKey(t),
		}
	}

	// Add our public key to the current validators set.
	publicKey, err := bandersnatch.Public(privateKey)
	require.NoError(t, err)
	currentValidators[1] = &crypto.ValidatorKey{
		Bandersnatch: publicKey,
	}

	state := &State{
		EntropyPool: [4]crypto.Hash{
			testutils.RandomHash(t),
			testutils.RandomHash(t),
			entropy,
			testutils.RandomHash(t),
		},
		ValidatorState: validator.ValidatorState{
			SafroleState: safrole.State{
				NextValidators: currentValidators,
			},
		},
	}

	// Set the ring commitment.
	ringCommitment, err := state.ValidatorState.SafroleState.CalculateRingCommitment()
	require.NoError(t, err)
	state.ValidatorState.SafroleState.RingCommitment = ringCommitment

	// Create a ticket proof.
	ticket, err := CreateTicketProof(state, privateKey, 0)
	require.NoError(t, err)

	// Verify the ticket proof.
	outputHash, err := VerifyTicketProof(state, ticket)
	require.NoError(t, err)

	require.NotEmpty(t, outputHash)
}

func TestCreateTicketProofInvalidState(t *testing.T) {
	privateKey := testutils.RandomBandersnatchPrivateKey(t)

	currentValidators := safrole.ValidatorsData{}
	for i := range currentValidators {
		currentValidators[i] = &crypto.ValidatorKey{
			// Invalid public keys. Can't be all zero'd out.
			Bandersnatch: crypto.BandersnatchPublicKey{},
		}
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
				NextValidators: currentValidators,
			},
		},
	}

	_, err := CreateTicketProof(state, privateKey, 0)
	require.Error(t, err)
}

func TestCreateTicketProofInvalidPrivateKey(t *testing.T) {
	privateKey := crypto.BandersnatchPrivateKey{}

	currentValidators := safrole.ValidatorsData{}
	for i := range currentValidators {
		currentValidators[i] = &crypto.ValidatorKey{
			Bandersnatch: testutils.RandomBandersnatchPublicKey(t),
		}
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
				NextValidators: currentValidators,
			},
		},
	}

	_, err := CreateTicketProof(state, privateKey, 0)
	require.Error(t, err)
}

func TestVerifyTicketProofInvalidState(t *testing.T) {
	entropy := testutils.RandomHash(t)
	privateKey := testutils.RandomBandersnatchPrivateKey(t)

	currentValidators := safrole.ValidatorsData{}
	for i := range currentValidators {
		currentValidators[i] = &crypto.ValidatorKey{
			Bandersnatch: testutils.RandomBandersnatchPublicKey(t),
		}
	}

	// Add our public key to the current validators set.
	publicKey, err := bandersnatch.Public(privateKey)
	require.NoError(t, err)
	currentValidators[1] = &crypto.ValidatorKey{
		Bandersnatch: publicKey,
	}

	state := &State{
		EntropyPool: [4]crypto.Hash{
			testutils.RandomHash(t),
			testutils.RandomHash(t),
			entropy,
			testutils.RandomHash(t),
		},
		ValidatorState: validator.ValidatorState{
			SafroleState: safrole.State{
				NextValidators: currentValidators,
			},
		},
	}

	// Create a ticket proof.
	ticket, err := CreateTicketProof(state, privateKey, 0)
	require.NoError(t, err)

	// Create invalid validators.
	incorrectValidators := safrole.ValidatorsData{}
	for i := range incorrectValidators {
		incorrectValidators[i] = &crypto.ValidatorKey{
			// Invalid public keys. Can't be all zero'd out.
			Bandersnatch: crypto.BandersnatchPublicKey{},
		}
	}
	state.ValidatorState.SafroleState.NextValidators = incorrectValidators
	// Set an empty ring commitment.
	state.ValidatorState.SafroleState.RingCommitment = crypto.RingCommitment{}

	_, err = VerifyTicketProof(state, ticket)
	require.Error(t, err)
}

func TestVerifyTicketProofInvalidTicketProof(t *testing.T) {
	currentValidators := safrole.ValidatorsData{}
	for i := range currentValidators {
		currentValidators[i] = &crypto.ValidatorKey{
			Bandersnatch: testutils.RandomBandersnatchPublicKey(t),
		}
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
				NextValidators: currentValidators,
			},
		},
	}

	// Set the ring commitment.
	ringCommitment, err := state.ValidatorState.SafroleState.CalculateRingCommitment()
	require.NoError(t, err)
	state.ValidatorState.SafroleState.RingCommitment = ringCommitment

	_, err = VerifyTicketProof(state, block.TicketProof{})
	require.Error(t, err)
}
