package state

import (
	"fmt"

	"github.com/eigerco/strawberry/internal/block"
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/crypto/bandersnatch"
	"github.com/eigerco/strawberry/internal/jamtime"
	"github.com/eigerco/strawberry/internal/safrole"
	"github.com/eigerco/strawberry/pkg/serialization"
	"github.com/eigerco/strawberry/pkg/serialization/codec"
)

const (
	ticketSealContext   = "$jam_ticket_seal"
	fallbackSealContext = "$jam_fallback_seal"
	entropyContext      = "$jam_entropy"
)

// TODO currently unused, should be used in section 19
// t ∈ {0, 1} 1 if ticket, 0 if fallback key
var T byte

// Gets the winning ticket or key for the current timeslot
func getWinningTicketOrKey(header *block.Header, state *State) (interface{}, error) {
	index := header.TimeSlotIndex % jamtime.TimeslotsPerEpoch
	sealingKeys, err := state.ValidatorState.SafroleState.SealingKeySeries.Value()
	if err != nil {
		return nil, err
	}
	switch value := sealingKeys.(type) {
	case safrole.TicketsBodies:
		return value[index], nil
	case crypto.EpochKeys:
		return value[index], nil
	default:
		return nil, fmt.Errorf("unexpected type in TicketsOrKeys: %T", value)
	}
}

// TODO: implement this function. This is just a mock.
func isWinningKey(key crypto.BandersnatchSerializedPublicKey, header *block.Header, state *State) bool {
	winningTicketOrKey, err := getWinningTicketOrKey(header, state)
	if err != nil {
		return false
	}
	return key == winningTicketOrKey
}

func encodeUnsealedHeader(header block.Header) ([]byte, error) {
	header.BlockSealSignature = crypto.BandersnatchSignature{}
	// Use the regular serialization from Appendix C
	serializer := serialization.NewSerializer(&codec.JAMCodec{})
	return serializer.Encode(header)
}

func buildSealContextForFallbackKeys(state *State) []byte {
	// Equation 60: γ's ∈ ⟦HB⟧
	context := append([]byte(fallbackSealContext), state.EntropyPool[3][:]...) // η_3
	T = 0
	return context
}
func buildSealContextForTickets(state *State, ticket block.Ticket) []byte {
	var context []byte
	// Equation 59: γ's ∈ ⟦C⟧
	context = append([]byte(ticketSealContext), state.EntropyPool[3][:]...) // η_3
	context = append(context, byte(ticket.EntryIndex))
	T = 1
	return context
}

func buildSealContext(header *block.Header, state *State) ([]byte, error) {
	var context []byte

	winningTicketOrKey, err := getWinningTicketOrKey(header, state)
	if err != nil {
		return nil, err
	}
	// case switch if winningTicketOrKey is of type crypto.BandersnatchPublicKey or block.Ticket
	switch tok := winningTicketOrKey.(type) {
	case block.Ticket:
		// Equation 59: γ's ∈ ⟦C⟧
		context = buildSealContextForTickets(state, tok)
	case crypto.BandersnatchPublicKey:
		// Equation 60: γ's ∈ ⟦HB⟧
		context = buildSealContextForFallbackKeys(state)
	default:
		return nil, fmt.Errorf("unknown sealing key type: %T", winningTicketOrKey)
	}
	return context, nil
}

func createSealSignature(header *block.Header, state *State, privateKey *bandersnatch.PrivateKey) error {
	context, err := buildSealContext(header, state)
	if err != nil {
		return err
	}

	unsealedHeader, err := encodeUnsealedHeader(*header)
	if err != nil {
		return err
	}
	message := append(unsealedHeader, context...)
	// Hs(BlockSealSignaure) ∈ FEU(H)Ha⟨...⟩
	header.BlockSealSignature, err = privateKey.Sign(message)

	return err
}

// Implements equation 61 Hv ∈ F[]Ha⟨XE ⌢ Y(Hs)⟩
func createVRFSignature(header *block.Header, privateKey *bandersnatch.PrivateKey) error {
	// XE is the constant context string
	XE := []byte("$jam_entropy")
	// Generate VRF proof for the seal signature
	sealVrfProof, err := privateKey.GenerateVrfProof(header.BlockSealSignature[:], XE)
	if err != nil {
		return err
	}
	// Generate VRF output from the proof (this is effectively Y(Hs))
	vrfOutput, err := bandersnatch.GenerateVrfOutput(sealVrfProof)
	if err != nil {
		return err
	}
	// Construct the message: XE ⌢ Y(Hs)
	message := append(XE, vrfOutput[:]...)
	// Sign the constructed message to get Hv
	signature, err := privateKey.Sign(message)
	if err != nil {
		return err
	}
	// Set the signature as Hv in the header
	header.VRFSignature = signature

	return nil
}

// Implements equations 66 and 67
func updateEntropyAccumulator(header *block.Header, state *State, privateKey *bandersnatch.PrivateKey) error {
	// Constants
	XE := []byte("$jam_entropy")

	// Generate VRF proof using the VRF signature as input
	vrfProof, err := privateKey.GenerateVrfProof(header.VRFSignature[:], XE)
	if err != nil {
		return err
	}

	// Generate VRF output from the proof
	vrfOutput, err := bandersnatch.GenerateVrfOutput(vrfProof)
	if err != nil {
		return err
	}

	// Equation 66: η'0 ≡ H(η0 ⌢ Y(Hv))
	newEntropy := append(state.EntropyPool[0][:], vrfOutput[:]...)
	state.EntropyPool[0] = crypto.Hash(newEntropy)

	// Equation 67: Rotate entropy accumulators on epoch change
	if header.TimeSlotIndex.IsFirstTimeslotInEpoch() {
		rotateEntropyPool(state)
	}

	return nil
}

func rotateEntropyPool(state *State) {
	state.EntropyPool[3] = state.EntropyPool[2]
	state.EntropyPool[2] = state.EntropyPool[1]
	state.EntropyPool[1] = state.EntropyPool[0]
}

// Should be called after a check if the validator has are winning key.
func sealBlockAndUpdateEntropy(header *block.Header, state *State, privateKey *bandersnatch.PrivateKey) error {
	if err := createSealSignature(header, state, privateKey); err != nil {
		return err
	}
	if err := createVRFSignature(header, privateKey); err != nil {
		return err
	}
	return updateEntropyAccumulator(header, state, privateKey)
}

// Main function to implement all of section 6.4
func AttemptBlockSealing(header *block.Header, state *State, privateKey *bandersnatch.PrivateKey) error {
	publicKey, err := privateKey.Public()
	if err != nil {
		return fmt.Errorf("failed to get public key: %w", err)
	}
	if !isWinningKey(publicKey, header, state) {
		return fmt.Errorf("key does not have privilege to seal the block")
	}
	if err := sealBlockAndUpdateEntropy(header, state, privateKey); err != nil {
		return fmt.Errorf("failed to seal block: %w", err)
	}
	return nil
}
