package block

import (
	"io"

	"github.com/eigerco/strawberry/internal/crypto"
)

const (
	TicketProofSize = 784 // Size of F̄[]γz⟨XT ⌢ η′2 r⟩
)

// Ticket represents a single ticket (C in equation 50)
type Ticket struct {
	Identifier crypto.BandersnatchOutputHash // y ∈ H 32bytes hash
	EntryIndex uint8                         // r ∈ Nn (0, 1)
}

// UnmarshalJAM implements the JAM codec Unmarshaler interface.
func (t *Ticket) UnmarshalJAM(r io.Reader) error {
	if _, err := io.ReadFull(r, t.Identifier[:]); err != nil {
		return err
	}
	var b [1]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return err
	}
	t.EntryIndex = b[0]
	return nil
}

func (t Ticket) TicketOrKeyType() {}

// TicketProof represents a proof of a valid ticket
type TicketProof struct {
	EntryIndex uint8                 // r ∈ Nn (0, 1)
	Proof      [TicketProofSize]byte // RingVRF proof
}

// UnmarshalJAM implements the JAM codec Unmarshaler interface.
func (tp *TicketProof) UnmarshalJAM(r io.Reader) error {
	var b [1]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return err
	}
	tp.EntryIndex = b[0]
	_, err := io.ReadFull(r, tp.Proof[:])
	return err
}

// TicketExtrinsic represents the E_T extrinsic
type TicketExtrinsic struct {
	TicketProofs []TicketProof
}
