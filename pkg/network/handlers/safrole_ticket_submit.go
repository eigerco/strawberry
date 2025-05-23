package handlers

import (
	"context"
	"crypto/ed25519"
	"fmt"

	"github.com/eigerco/strawberry/internal/block"
	"github.com/eigerco/strawberry/internal/jamtime"
	"github.com/eigerco/strawberry/internal/state"
	"github.com/eigerco/strawberry/internal/store"
	"github.com/eigerco/strawberry/internal/validator"
	"github.com/eigerco/strawberry/pkg/serialization/codec/jam"
	"github.com/quic-go/quic-go"
)

// SafroleTicketSubmitRequestHandler handles CE 131 Safrole ticket submission protocol.
// This is the first step in the two-phase ticket distribution process where
// a generating validator sends their ticket to a deterministically-selected proxy validator.
//
// Protocol Flow (CE 131):
// 1. Validator generates Safrole ticket for current epoch
// 2. Validator determines proxy using: last 4 bytes of VRF output % validator_count
// 3. Validator sends ticket to proxy validator (this handler receives it)
// 4. Proxy validates ticket and stores it for later distribution (CE 132)
type SafroleTicketSubmitRequestHandler struct {
	safroleTicketHandler
}

// SafroleTicketDistributionRequestHandler handles CE 132 Safrole ticket distribution protocol.
// This is the second step where the proxy validator broadcasts the received ticket
// to all current validators for use in block production.
//
// Protocol Flow (CE 132):
// 1. Proxy validator receives ticket via CE 131 (handled by submit handler above)
// 2. After timing delay (3 minutes), proxy broadcasts to ALL current validators
// 3. Current validators receive ticket via this handler
// 4. Validators store ticket for potential use in block sealing
type SafroleTicketDistributionRequestHandler struct {
	safroleTicketHandler
}

// safroleTicketHandler contains the common logic for both CE 131 and CE 132 protocols.
// Both protocols use identical wire format but different StreamKind and serve different roles in the distribution process.
type safroleTicketHandler struct {
	state            *state.State
	validatorManager *validator.ValidatorManager
	store            *store.Ticket
}

// NewSafroleTicketSubmitRequestHandler creates a handler for CE 131 (ticket submission).
// This handler receives tickets from generating validators and validates that
// the current node is the correct proxy for the ticket.
func NewSafroleTicketSubmitRequestHandler(state *state.State, vm *validator.ValidatorManager, store *store.Ticket) *SafroleTicketSubmitRequestHandler {
	return &SafroleTicketSubmitRequestHandler{
		safroleTicketHandler: safroleTicketHandler{
			state:            state,
			validatorManager: vm,
			store:            store,
		},
	}
}

// NewSafroleTicketBroadcastRequestHandler creates a handler for CE 132 (ticket distribution).
// This handler receives tickets from proxy validators during the broadcast phase.
// All current validators should receive tickets via this handler.
func NewSafroleTicketBroadcastRequestHandler(state *state.State, vm *validator.ValidatorManager, store *store.Ticket) *SafroleTicketDistributionRequestHandler {
	return &SafroleTicketDistributionRequestHandler{
		safroleTicketHandler: safroleTicketHandler{
			state:            state,
			validatorManager: vm,
			store:            store,
		},
	}
}

// safroleTicketSubmitMessage represents the wire format for both CE 131 and CE 132.
// The message contains the epoch index (when ticket will be used) and the ticket proof itself.
type safroleTicketSubmitMessage struct {
	EpochIndex  jamtime.Epoch
	TicketProof block.TicketProof
}

// HandleStream implements CE 131 Safrole ticket submission protocol.
// This method receives tickets from generating validators and validates that
// the current node is the designated proxy for the ticket.
//
// Validation Process:
// 1. Verify ticket proof against ring commitment
// 2. Check that this node is the correct proxy (based on VRF output)
// 3. Store ticket for later distribution via CE 132
func (h *SafroleTicketSubmitRequestHandler) HandleStream(ctx context.Context, stream quic.Stream, peerKey ed25519.PublicKey) error {
	return handleSafroleTicket(ctx, stream, &h.safroleTicketHandler, true)
}

// HandleStream implements CE 132 Safrole ticket distribution protocol.
// This method receives tickets from proxy validators during the broadcast phase.
// All current validators should receive and store these tickets.
//
// Storage Process:
// 1. Verify ticket proof is valid
// 2. Store ticket for potential use in block sealing
// 3. Ticket becomes available for lottery participation
func (h *SafroleTicketDistributionRequestHandler) HandleStream(ctx context.Context, stream quic.Stream, peerKey ed25519.PublicKey) error {
	return handleSafroleTicket(ctx, stream, &h.safroleTicketHandler, false)
}

// TODO: This will probably split into two functions, one for CE 131 and one for CE 132,
// as the runtime becomes more complete. Currently we just save all the tickets, when complete
// it will probably not be the case.
// handleSafroleTicket implements the common wire protocol for both CE 131 and CE 132.
// If requireProxyValidation is true, it checks if the current node is the correct proxy for the ticket.
// If false, it assumes the ticket is from a proxy validator and skips the proxy check.
// Wire Protocol (both CE 131 and CE 132):
// --> Epoch Index ++ Ticket (Epoch index identifies when ticket will be used)
// --> FIN
// <-- FIN
// Validation Steps:
// 1. Parse epoch index and ticket proof from message
// 2. Verify RingVRF proof against current ring commitment
// 3. For CE 131: Check this node is correct proxy for the ticket
// 4. Store ticket with computed hash for future use
//
// Security Notes:
// - Ticket proofs are verified against the ring commitment of next epoch validators
// - Proxy validation ensures tickets are only accepted by designated recipients
// - Invalid tickets are rejected to prevent spam and ensure lottery integrity
func handleSafroleTicket(ctx context.Context, stream quic.Stream, handler *safroleTicketHandler, requireProxyValidation bool) error {
	msg, err := ReadMessageWithContext(ctx, stream)
	if err != nil {
		return fmt.Errorf("read request message: %w", err)
	}

	if len(msg.Content) < 4+1+block.TicketProofSize { // epoch index 4 + attempt 1 + ticket proof 784 = 789
		return fmt.Errorf("message too short")
	}

	// Deserialize the message into structured format
	var request safroleTicketSubmitMessage
	if err := jam.Unmarshal(msg.Content, &request); err != nil {
		return fmt.Errorf("unmarshal message: %w", err)
	}

	// Get the ring commitment for the next epoch's validators
	// This is used to verify the RingVRF proof in the ticket
	// TODO: Deal with epoch change.
	ringCommitment := handler.state.ValidatorState.SafroleState.RingCommitment

	// Verify the ticket proof and extract the VRF hash
	// The hash is used to determine the correct proxy validator
	hash, err := state.VerifyTicketProof(ringCommitment, handler.state.EntropyPool[2], request.TicketProof)
	if err != nil {
		return fmt.Errorf("verify ticket proof: %w", err)
	}

	// For CE 131: Verify this node is the designated proxy for this ticket
	// For CE 132: This check should be skipped as all validators should accept broadcast tickets. requireProxyValidation should be true.
	if requireProxyValidation && !handler.validatorManager.IsProxyValidatorFor(hash) {
		return fmt.Errorf("not proxy validator for hash %v", hash)
	}

	// Store the ticket for future use in block production
	// Tickets are indexed by epoch and hash for efficient retrieval
	if err = handler.store.PutTicket(uint32(jamtime.CurrentEpoch()), request.TicketProof, hash); err != nil {
		return fmt.Errorf("put ticket: %w", err)
	}

	// Close the stream to complete the protocol exchange
	if err := stream.Close(); err != nil {
		return fmt.Errorf("close stream: %w", err)
	}

	return nil
}

// SafroleTicketSubmiter handles the client side of both CE 131 and CE 132 protocols.
// It formats and sends ticket submission/distribution requests to other validators.
type SafroleTicketSubmiter struct{}

// Submit implements the client side of CE 131/132 Safrole ticket protocols.
// This method is used by:
//   - CE 131: Generating validators to send tickets to proxy validators
//   - CE 132: Proxy validators to broadcast tickets to all current validators
//     Which protocol is used depends on the stream kind of the connection.
//
// Wire Protocol:
// --> Epoch Index ++ Ticket (Epoch index identifies when ticket will be used)
// --> FIN
// <-- FIN
func (r *SafroleTicketSubmiter) Submit(ctx context.Context, stream quic.Stream, ticketProof block.TicketProof) error {
	// Create the message with epoch index and ticket proof
	msg := safroleTicketSubmitMessage{
		EpochIndex:  jamtime.CurrentEpoch(), // When the ticket will be used
		TicketProof: ticketProof,            // The actual RingVRF proof (784 bytes)
	}

	// Serialize the message for transmission
	request, err := jam.Marshal(msg)
	if err != nil {
		return fmt.Errorf("marshal request: %w", err)
	}

	// Send the serialized message over the stream
	if err := WriteMessageWithContext(ctx, stream, request); err != nil {
		return fmt.Errorf("write request message: %w", err)
	}

	// Close the stream to signal completion (triggers FIN)
	if err := stream.Close(); err != nil {
		return fmt.Errorf("close stream: %w", err)
	}

	return nil
}
