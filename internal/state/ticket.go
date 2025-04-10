package state

import (
	"errors"

	"github.com/eigerco/strawberry/internal/block"
	"github.com/eigerco/strawberry/internal/common"
	"github.com/eigerco/strawberry/internal/crypto"
)

// Creates a ticket proof as per equation 6.29 in the graypaper (v0.6.4)
// The ticket extrinic is a sequence of ticket proofs.
func CreateTicketProof(state *State, privateKey crypto.BandersnatchPrivateKey, attempt uint8) (block.TicketProof, error) {
	if attempt > common.MaxTicketAttempts {
		return block.TicketProof{}, errors.New("attempts exceeded")
	}

	ringProver, err := state.ValidatorState.SafroleState.RingProver(privateKey)
	defer ringProver.Free()
	if err != nil {
		return block.TicketProof{}, err
	}

	// Build the context: XT ⌢ η′2 ++ ir
	context := buildTicketSealContext(state.EntropyPool[2], attempt)
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
func VerifyTicketProof(state *State, ticket block.TicketProof) (crypto.BandersnatchOutputHash, error) {
	// TODO: if this is too expensive to construct each time we should pass it in.
	ringVerifier, err := state.ValidatorState.SafroleState.RingVerifier()
	defer ringVerifier.Free()
	if err != nil {
		return crypto.BandersnatchOutputHash{}, err
	}

	if ticket.EntryIndex >= common.MaxTicketAttempts {
		return crypto.BandersnatchOutputHash{}, errors.New("bad ticket attempt")
	}

	// Build the context: XT ⌢ η′2 ++ ir
	context := buildTicketSealContext(state.EntropyPool[2], ticket.EntryIndex)
	ok, outputHash := ringVerifier.Verify(context, []byte{}, state.ValidatorState.SafroleState.RingCommitment, ticket.Proof)
	if !ok {
		return crypto.BandersnatchOutputHash{}, errors.New("bad ticket proof")
	}

	return outputHash, nil
}
