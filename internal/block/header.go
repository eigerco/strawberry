package block

import (
	"fmt"
	"io"

	"github.com/eigerco/strawberry/internal/crypto/ed25519"

	"github.com/eigerco/strawberry/internal/constants"
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/jamtime"
	"github.com/eigerco/strawberry/pkg/serialization/codec/jam"
)

// Header as defined in the section 5 in the paper
type Header struct {
	ParentHash           crypto.Hash                  // Hp
	PriorStateRoot       crypto.Hash                  // Hr
	ExtrinsicHash        crypto.Hash                  // Hx
	TimeSlotIndex        jamtime.Timeslot             // Ht
	EpochMarker          *EpochMarker                 // He
	WinningTicketsMarker *WinningTicketMarker         // Hw
	BlockAuthorIndex     uint16                       // Hi
	VRFSignature         crypto.BandersnatchSignature // Hv
	OffendersMarkers     []ed25519.PublicKey          // Ho, the culprit's and fault's public keys
	BlockSealSignature   crypto.BandersnatchSignature // Hs
}

type ValidatorKeys struct {
	Bandersnatch crypto.BandersnatchPublicKey
	Ed25519      ed25519.PublicKey
}

// UnmarshalJAM implements the JAM codec Unmarshaler interface.
func (vk *ValidatorKeys) UnmarshalJAM(r io.Reader) error {
	if _, err := io.ReadFull(r, vk.Bandersnatch[:]); err != nil {
		return err
	}
	vk.Ed25519 = make([]byte, crypto.Ed25519PublicSize)
	_, err := io.ReadFull(r, vk.Ed25519)
	return err
}

// EpochMarker consists of epoch randomness and a sequence of
// Bandersnatch keys defining the Bandersnatch validator keys (kb) beginning in the next epoch.
type EpochMarker struct {
	Entropy        crypto.Hash
	TicketsEntropy crypto.Hash
	Keys           [constants.NumberOfValidators]ValidatorKeys
}

// UnmarshalJAM implements the JAM codec Unmarshaler interface.
func (em *EpochMarker) UnmarshalJAM(r io.Reader) error {
	if _, err := io.ReadFull(r, em.Entropy[:]); err != nil {
		return err
	}
	if _, err := io.ReadFull(r, em.TicketsEntropy[:]); err != nil {
		return err
	}
	for i := range em.Keys {
		if err := em.Keys[i].UnmarshalJAM(r); err != nil {
			return err
		}
	}
	return nil
}

type WinningTicketMarker [constants.TimeslotsPerEpoch]Ticket

// UnmarshalJAM implements the JAM codec Unmarshaler interface.
func (wtm *WinningTicketMarker) UnmarshalJAM(r io.Reader) error {
	for i := range wtm {
		if err := wtm[i].UnmarshalJAM(r); err != nil {
			return err
		}
	}
	return nil
}

// Hash returns the hash of the header
func (h Header) Hash() (crypto.Hash, error) {
	jamBytes, err := jam.Marshal(h)
	if err != nil {
		return crypto.Hash{}, fmt.Errorf("marshal header: %w", err)
	}
	return crypto.HashData(jamBytes), nil
}

// Bytes returns the Jam encoded bytes of the header
func (h Header) Bytes() ([]byte, error) {
	return jam.Marshal(h)
}

// HeaderFromBytes unmarshals a header from Jam encoded bytes
func HeaderFromBytes(data []byte) (Header, error) {
	var header Header
	if err := jam.Unmarshal(data, &header); err != nil {
		return Header{}, fmt.Errorf("unmarshal header: %w", err)
	}
	return header, nil
}
