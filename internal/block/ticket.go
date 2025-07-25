package block

import "github.com/eigerco/strawberry/internal/crypto"

const (
	MaxTicketsPerBlock = 16  // `K` in the paper. The maximum number of tickets which may be submitted in a single extrinsic.
	TicketProofSize    = 784 // Size of F̄[]γz⟨XT ⌢ η′2 r⟩
)

// Ticket represents a single ticket (C in equation 50)
type Ticket struct {
	Identifier crypto.BandersnatchOutputHash // y ∈ H 32bytes hash
	EntryIndex uint8                         // r ∈ Nn (0, 1)
}

func (t Ticket) TicketOrKeyType() {}

// TicketProof represents a proof of a valid ticket
type TicketProof struct {
	EntryIndex uint8                 // r ∈ Nn (0, 1)
	Proof      [TicketProofSize]byte // RingVRF proof
}

// TicketExtrinsic represents the E_T extrinsic
type TicketExtrinsic struct {
	TicketProofs []TicketProof
}
