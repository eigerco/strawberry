package state

import (
	"testing"

	"github.com/eigerco/strawberry/internal/block"
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/crypto/bandersnatch"
	"github.com/eigerco/strawberry/internal/safrole"
	"github.com/eigerco/strawberry/internal/testutils"
	"github.com/stretchr/testify/require"
)

func TestCreateVerifyTicketProof(t *testing.T) {
	entropy := testutils.RandomHash(t)
	privateKey := testutils.RandomBandersnatchPrivateKey(t)

	pendingValidators := safrole.ValidatorsData{}
	for i := range pendingValidators {
		pendingValidators[i] = crypto.ValidatorKey{
			Bandersnatch: testutils.RandomBandersnatchPublicKey(t),
		}
	}

	// Add our public key to the current validators set.
	publicKey, err := bandersnatch.Public(privateKey)
	require.NoError(t, err)
	pendingValidators[1] = crypto.ValidatorKey{
		Bandersnatch: publicKey,
	}

	// Set the ring commitment.
	ringCommitment, err := pendingValidators.RingCommitment()
	require.NoError(t, err)

	// Create a ticket proof.
	ticket, err := CreateTicketProof(pendingValidators, entropy, privateKey, 0)
	require.NoError(t, err)

	// Verify the ticket proof.
	outputHash, err := VerifyTicketProof(ringCommitment, entropy, ticket)
	require.NoError(t, err)

	require.NotEmpty(t, outputHash)
}

func TestCreateTicketProofInvalidValidators(t *testing.T) {
	privateKey := testutils.RandomBandersnatchPrivateKey(t)

	pendingValidators := safrole.ValidatorsData{}
	for i := range pendingValidators {
		pendingValidators[i] = crypto.ValidatorKey{
			// Invalid public keys. Can't be all zero'd out.
			Bandersnatch: crypto.BandersnatchPublicKey{},
		}
	}

	_, err := CreateTicketProof(pendingValidators, testutils.RandomHash(t), privateKey, 0)
	require.Error(t, err)
}

func TestCreateTicketProofInvalidPrivateKey(t *testing.T) {
	privateKey := crypto.BandersnatchPrivateKey{}

	pendingValidators := safrole.ValidatorsData{}
	for i := range pendingValidators {
		pendingValidators[i] = crypto.ValidatorKey{
			Bandersnatch: testutils.RandomBandersnatchPublicKey(t),
		}
	}
	_, err := CreateTicketProof(pendingValidators, testutils.RandomHash(t), privateKey, 0)
	require.Error(t, err)
}

func TestVerifyTicketProofInvalidValidators(t *testing.T) {
	entropy := testutils.RandomHash(t)
	privateKey := testutils.RandomBandersnatchPrivateKey(t)

	pendingValidators := safrole.ValidatorsData{}
	for i := range pendingValidators {
		pendingValidators[i] = crypto.ValidatorKey{
			Bandersnatch: testutils.RandomBandersnatchPublicKey(t),
		}
	}

	// Add our public key to the current validators set.
	publicKey, err := bandersnatch.Public(privateKey)
	require.NoError(t, err)
	pendingValidators[1] = crypto.ValidatorKey{
		Bandersnatch: publicKey,
	}

	// Create a ticket proof.
	ticket, err := CreateTicketProof(pendingValidators, entropy, privateKey, 0)
	require.NoError(t, err)

	// Use an empty ring commitment. Should error.
	_, err = VerifyTicketProof(crypto.RingCommitment{}, entropy, ticket)
	require.Error(t, err)
}

func TestVerifyTicketProofInvalidTicketProof(t *testing.T) {
	pendingValidators := safrole.ValidatorsData{}
	for i := range pendingValidators {
		pendingValidators[i] = crypto.ValidatorKey{
			Bandersnatch: testutils.RandomBandersnatchPublicKey(t),
		}
	}

	// Set the ring commitment.
	ringCommitment, err := pendingValidators.RingCommitment()
	require.NoError(t, err)

	_, err = VerifyTicketProof(ringCommitment, testutils.RandomHash(t), block.TicketProof{})
	require.Error(t, err)
}
