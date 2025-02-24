package state

import (
	"errors"
	"fmt"

	"github.com/eigerco/strawberry/pkg/serialization/codec/jam"

	"github.com/eigerco/strawberry/internal/block"
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/crypto/bandersnatch"
	"github.com/eigerco/strawberry/internal/safrole"
)

const (
	TicketSealContext   = "jam_ticket_seal"
	FallbackSealContext = "jam_fallback_seal"
	EntropyContext      = "jam_entropy"
)

var (
	ErrBlockSealInvalidAuthor = errors.New("invalid block seal author")
)

// This represents a union of either a block.Ticket or a
// crypto.BandersnatchPublic key as a fallback.
type TicketOrKey interface {
	TicketOrKeyType()
}

// Gets the winning ticket or key for the current timeslot.
// Implements part of equation 6.15 in the graypaper: γ′s[Ht]^↺ (v0.5.4)
func getWinningTicketOrKey(header *block.Header, state *State) (TicketOrKey, error) {
	index := header.TimeSlotIndex.TimeslotInEpoch()
	sealingKeys := state.ValidatorState.SafroleState.SealingKeySeries.Get()
	switch value := sealingKeys.(type) {
	case safrole.TicketsBodies:
		return value[index], nil
	case crypto.EpochKeys:
		return value[index], nil
	default:
		return nil, fmt.Errorf("unexpected type in TicketsOrKeys: %T", value)
	}
}

// Attempts to a seal a block and add a block seal signature (Hs) and a VRFS
// signature (Hv) to the header. Uses either a ticket in most cases but uses a
// bandersnatch public key as a fallback. Checks that the private key given was
// either used to generate the winning ticket or otherwise if it's public key
// matches the winning public key in the case of fallback.
// Implements equations 6.15-6.20 in the graypaper. (v0.5.4)
func SealBlock(
	header *block.Header,
	state *State,
	privateKey crypto.BandersnatchPrivateKey,
) error {
	winningTicketOrKey, err := getWinningTicketOrKey(header, state)
	if err != nil {
		return err
	}

	entropy := state.EntropyPool[3] // η_3

	var (
		sealSignature crypto.BandersnatchSignature
		vrfSignature  crypto.BandersnatchSignature
	)

	sealSignature, vrfSignature, err = SignBlock(*header, winningTicketOrKey, privateKey, entropy)
	if err != nil {
		return err
	}

	header.BlockSealSignature = sealSignature
	header.VRFSignature = vrfSignature

	return nil
}

// Produces a seal signature and VRFS signature for the unsealed header bytes of
// the given header using either a winning ticket or a public key in the case of
// fallback. This will error if the private key can't be associated with the
// given ticket or public key in the case of fallback.
// Implements equations 6.15-6.20 in the graypaper. (v0.5.4)
func SignBlock(
	header block.Header,
	ticketOrKey TicketOrKey,
	privateKey crypto.BandersnatchPrivateKey, // Ha
	entropy crypto.Hash, // η′3
) (
	sealSignature crypto.BandersnatchSignature,
	vrfSignature crypto.BandersnatchSignature,
	err error,
) {
	switch tok := ticketOrKey.(type) {
	case block.Ticket:
		return SignBlockWithTicket(header, tok, privateKey, entropy)
	case crypto.BandersnatchPublicKey:
		return SignBlockWithFallback(header, tok, privateKey, entropy)
	default:
		return crypto.BandersnatchSignature{}, crypto.BandersnatchSignature{}, fmt.Errorf("unexpected type for ticketOrKey: %T", tok)
	}
}

// Produces a seal signature and VRFS signature for the unsealed header bytes of
// the given header using a winning ticket. This will error if the private key
// can't be associated with the given ticket.
// Implements equations 6.15 and 6.17-6.20 in the graypaper. (v0.5.4)
func SignBlockWithTicket(
	header block.Header,
	ticket block.Ticket,
	privateKey crypto.BandersnatchPrivateKey, // Ha
	entropy crypto.Hash, // η′3
) (
	sealSignature crypto.BandersnatchSignature,
	vrfSignature crypto.BandersnatchSignature,
	err error,
) {

	// Build the context: XT ⌢ η′3 ++ ir
	sealContext := buildTicketSealContext(entropy, ticket.EntryIndex)

	// We need to add the VRF signature to the header before we seal. This seems
	// like a circle dependency, but it's actually not. To get around this we
	// can sign without the aux data (unsealed header), since the seal output
	// hash, Y(Hs) will be the same regardless of aux. We then use this to
	// produce the VRF signature and add it to the header before we do the final
	// seal.
	sealVRFSignature, err := bandersnatch.Sign(privateKey, sealContext, []byte{})
	if err != nil {
		return crypto.BandersnatchSignature{}, crypto.BandersnatchSignature{}, err
	}

	sealOutputHash, err := bandersnatch.OutputHash(sealVRFSignature)
	if err != nil {
		return crypto.BandersnatchSignature{}, crypto.BandersnatchSignature{}, err
	}

	// Extra safety check. See equation 6.29 in the graypaper. (v0.5.4)
	// The VRF output hash of the seal signature should be the same as the VRF
	// output hash of the ticket if the same private key was used to produce
	// both.
	if sealOutputHash != ticket.Identifier {
		return crypto.BandersnatchSignature{}, crypto.BandersnatchSignature{}, ErrBlockSealInvalidAuthor
	}

	vrfSignature, err = signBlockVRFS(sealOutputHash, privateKey)
	if err != nil {
		return crypto.BandersnatchSignature{}, crypto.BandersnatchSignature{}, err
	}

	// Final seal including the VRF signature added to the header.
	header.VRFSignature = vrfSignature
	unsealedHeader, err := encodeUnsealedHeader(header)
	if err != nil {
		return crypto.BandersnatchSignature{}, crypto.BandersnatchSignature{}, err
	}

	sealSignature, err = bandersnatch.Sign(privateKey, sealContext, unsealedHeader)
	if err != nil {
		return crypto.BandersnatchSignature{}, crypto.BandersnatchSignature{}, err
	}

	return sealSignature, vrfSignature, nil
}

// Helper to build the ticket sealing context.
func buildTicketSealContext(entropy crypto.Hash, ticketAttempt uint8) []byte {
	// Build the context: XT ⌢ η′3 ++ ir
	sealContext := append([]byte(TicketSealContext), entropy[:]...)
	sealContext = append(sealContext, byte(ticketAttempt))
	return sealContext
}

// Produces a seal signature and VRFS signature for the unsealed header bytes of
// the given header using a winning public key. This is the fallback case. This
// will error if the private key can't be associated with the given public key.
// Implements equations 6.16 and 6.17-6.20 in the graypaper. (v0.5.4)
func SignBlockWithFallback(
	header block.Header,
	winningKey crypto.BandersnatchPublicKey,
	privateKey crypto.BandersnatchPrivateKey, // Ha
	entropy crypto.Hash, // // η′3
) (
	sealSignature crypto.BandersnatchSignature,
	vrfSignature crypto.BandersnatchSignature,
	err error,
) {
	// Extra safety check. Ha's public key should match the winning public key.
	ownerPublicKey, err := bandersnatch.Public(privateKey)
	if err != nil {
		return crypto.BandersnatchSignature{}, crypto.BandersnatchSignature{}, err
	}
	if ownerPublicKey != winningKey {
		return crypto.BandersnatchSignature{}, crypto.BandersnatchSignature{}, ErrBlockSealInvalidAuthor
	}

	// Build the context: XF ⌢ η′3
	sealContext := buildTicketFallbackContext(entropy)

	// Get Y(Hs) so we can produce and add the VRF signature to the header
	// before we do the final seal.
	sealVRFSignature, err := bandersnatch.Sign(privateKey, sealContext, []byte{})
	if err != nil {
		return crypto.BandersnatchSignature{}, crypto.BandersnatchSignature{}, err
	}

	sealOutputHash, err := bandersnatch.OutputHash(sealVRFSignature)
	if err != nil {
		return crypto.BandersnatchSignature{}, crypto.BandersnatchSignature{}, err
	}

	vrfSignature, err = signBlockVRFS(sealOutputHash, privateKey)
	if err != nil {
		return crypto.BandersnatchSignature{}, crypto.BandersnatchSignature{}, err
	}

	// Final sealing using the included VRF signature.
	header.VRFSignature = vrfSignature
	unsealedHeader, err := encodeUnsealedHeader(header)
	if err != nil {
		return crypto.BandersnatchSignature{}, crypto.BandersnatchSignature{}, err
	}

	sealSignature, err = bandersnatch.Sign(privateKey, sealContext, unsealedHeader)
	if err != nil {
		return crypto.BandersnatchSignature{}, crypto.BandersnatchSignature{}, err
	}

	return sealSignature, vrfSignature, nil
}

// Helper to build the fallback sealing context.
func buildTicketFallbackContext(entropy crypto.Hash) []byte {
	// Build the context: XF ⌢ η′3
	return append([]byte(FallbackSealContext), entropy[:]...)
}

// Helper to produce the VRFS signature.
// Implements equation 6.17 in the graypaper. (v0.5.4)
func signBlockVRFS(
	sealOutputHash crypto.BandersnatchOutputHash,
	privateKey crypto.BandersnatchPrivateKey,
) (crypto.BandersnatchSignature, error) {
	// Construct the message: XE ⌢ Y(Hs)
	vrfContext := buildVRFContext(sealOutputHash)

	// Sign the constructed message to get Hv.
	vrfSignature, err := bandersnatch.Sign(privateKey, vrfContext, []byte{})
	if err != nil {
		return crypto.BandersnatchSignature{}, err
	}

	return vrfSignature, nil
}

// Helper to build the fallback sealing context.
func buildVRFContext(sealOutputHash crypto.BandersnatchOutputHash) []byte {
	// Construct the message: XE ⌢ Y(Hs)
	return append([]byte(EntropyContext), sealOutputHash[:]...)
}

// Help to get unsealed header bytes. Essentially this strips off the header
// seal.
func encodeUnsealedHeader(header block.Header) ([]byte, error) {
	// Use the regular serialization from Appendix C in the graypaper.
	bytes, err := jam.Marshal(header)
	if err != nil {
		return nil, err
	}
	// Hs will be the last 96 zeros, so strip those off to get the unsealed
	// header bytes.
	// See equation C.19 in the graypaper. (v0.5.4)
	return bytes[:len(bytes)-96], nil
}

func VerifyBlockSeal(
	header *block.Header,
	state *State,
) (bool, error) {
	winningTicketOrKey, err := getWinningTicketOrKey(header, state)
	if err != nil {
		return false, err
	}

	entropy := state.EntropyPool[3] // η_3

	return VerifyBlockSignatures(*header, winningTicketOrKey, state.ValidatorState.CurrentValidators, entropy)
}

func VerifyBlockSignatures(
	header block.Header,
	ticketOrKey TicketOrKey,
	currentValidators safrole.ValidatorsData,
	entropy crypto.Hash,
) (bool, error) {
	unsealedHeader, err := encodeUnsealedHeader(header)
	if err != nil {
		return false, err
	}

	sealOutputHash, err := bandersnatch.OutputHash(header.BlockSealSignature)
	if err != nil {
		return false, err
	}

	switch tok := ticketOrKey.(type) {
	// The ticket case is more challenging because we don't immediately know the
	// public key of the validator who signed.
	case block.Ticket:
		// Sanity check.
		if sealOutputHash != tok.Identifier {
			return false, nil
		}

		sealContext := buildTicketSealContext(entropy, tok.EntryIndex)
		publicKey := crypto.BandersnatchPublicKey{}

		// Since the original ticket submission was anonymous we need to figure
		// out which validator signed. We do this by looping through all
		// currentValidators and seeing which validator's bandersnatch public
		// key is able to verify the seal signature.
		for _, keys := range currentValidators {
			if keys == nil {
				continue
			}

			ok, _ := bandersnatch.Verify(
				keys.Bandersnatch,
				sealContext,
				unsealedHeader,
				header.BlockSealSignature,
			)
			if ok {
				publicKey = keys.Bandersnatch
				break
			}
		}

		if publicKey == (crypto.BandersnatchPublicKey{}) {
			return false, nil
		}

		// Use the found public key to also check the VRF signature.
		ok, _ := bandersnatch.Verify(
			publicKey,
			buildVRFContext(sealOutputHash),
			[]byte{},
			header.VRFSignature,
		)
		if !ok {
			return false, nil
		}
		return true, nil

	// This case is much easier since we actually know the public key from the
	// start.
	case crypto.BandersnatchPublicKey:
		ok, _ := bandersnatch.Verify(
			tok,
			buildTicketFallbackContext(entropy),
			unsealedHeader,
			header.BlockSealSignature,
		)
		if !ok {
			return false, nil
		}
		ok, _ = bandersnatch.Verify(
			tok,
			buildVRFContext(sealOutputHash),
			[]byte{},
			header.VRFSignature,
		)
		if !ok {
			return false, nil
		}
		return true, nil
	default:
		return false, fmt.Errorf("unexpected type for ticketOrKey: %T", tok)
	}
}
