package state

import (
	"errors"

	"github.com/eigerco/strawberry/internal/block"
	"github.com/eigerco/strawberry/internal/common"
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/safrole"

	"github.com/eigerco/strawberry/internal/crypto/bandersnatch"
)

// Creates a ticket proof as per equation 6.29 in the graypaper (v0.6.4)
// The ticket extrinic is a sequence of ticket proofs.
func CreateTicketProof(pendingValidators safrole.ValidatorsData, entropy crypto.Hash, privateKey crypto.BandersnatchPrivateKey, attempt uint8) (block.TicketProof, error) {
	if attempt > common.MaxTicketAttemptsPerValidator {
		return block.TicketProof{}, errors.New("attempts exceeded")
	}

	ringProver, err := pendingValidators.RingProver(privateKey)
	defer ringProver.Free()
	if err != nil {
		return block.TicketProof{}, err
	}

	// Build the context: XT ⌢ η′2 ++ ir
	context := buildTicketSealContext(entropy, attempt)
	// Produce an anonymous ring signature.
	signature, err := ringProver.Sign(context, []byte{})
	if err != nil {
		return block.TicketProof{}, err
	}

	ticket := block.TicketProof{
		EntryIndex: attempt,
		Proof:      signature,
	}

	return ticket, nil
}

// Verifies a ticket proof as per equation 6.29 in the graypaper (v0.6.4)
// Returns the output hash / identifier of the ticket if the proof is valid, or
// an error if it is not.
func VerifyTicketProof(ringCommitment crypto.RingCommitment, entropy crypto.Hash, ticket block.TicketProof) (crypto.BandersnatchOutputHash, error) {
	// TODO: if this is too expensive to construct each time we should pass it in.
	// TODO: this should be replaced by a function call to verify a ring
	// signature without the need to construct a ring verifier at all.
	ringVerifier, err := bandersnatch.NewRingVerifier([]crypto.BandersnatchPublicKey{}) // Pass an empty ring since we're only going to be verifying.
	defer ringVerifier.Free()
	if err != nil {
		return crypto.BandersnatchOutputHash{}, err
	}

	if ticket.EntryIndex >= common.MaxTicketAttemptsPerValidator {
		return crypto.BandersnatchOutputHash{}, errors.New("bad ticket attempt")
	}

	// Build the context: XT ⌢ η′2 ++ ir
	context := buildTicketSealContext(entropy, ticket.EntryIndex)
	ok, outputHash := ringVerifier.Verify(context, []byte{}, ringCommitment, ticket.Proof)
	if !ok {
		return crypto.BandersnatchOutputHash{}, errors.New("bad ticket proof")
	}

	return outputHash, nil
}
