package block

import "github.com/eigerco/strawberry/internal/crypto"

const (
	maxTicketsPerBlock = 16  // `K` in the paper. The maximum number of tickets which may be submitted in a single extrinsic.
	ticketProofSize    = 784 // Size of F̄[]γz⟨XT ⌢ η′2 r⟩
)

// Ticket represents a single ticket (C in equation 50)
type Ticket struct {
	Identifier crypto.Hash // y ∈ H 32bytes hash
	EntryIndex uint8       // r ∈ Nn (0, 1)
}

// TicketProof represents a proof of a valid ticket
type TicketProof struct {
	EntryIndex uint8                 // r ∈ Nn (0, 1)
	Proof      [ticketProofSize]byte // RingVRF proof
}

// TicketExtrinsic represents the E_T extrinsic
type TicketExtrinsic struct {
	TicketProofs []TicketProof
}

// TODO: Bandersnatch. This is just a mock.
func ExtractTicketFromProof(proofs []TicketProof) []Ticket {
	result:= make([]Ticket, len(proofs))
	for i, proof := range proofs {
		result[i] = Ticket{
			EntryIndex: proof.EntryIndex, 
			Identifier: crypto.Hash(proof.Proof[:32]),
			}
	}
	return result
}
