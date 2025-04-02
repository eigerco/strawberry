package block

import (
	"crypto/ed25519"
	"fmt"

	"github.com/eigerco/strawberry/internal/common"
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
	OffendersMarkers     []ed25519.PublicKey          // Ho, the culprit's and fault's public keys
	BlockAuthorIndex     uint16                       // Hi
	VRFSignature         crypto.BandersnatchSignature // Hv
	BlockSealSignature   crypto.BandersnatchSignature // Hs
}

type ValidatorKeys struct {
	Bandersnatch crypto.BandersnatchPublicKey
	Ed25519      ed25519.PublicKey
}

// EpochMarker consists of epoch randomness and a sequence of
// Bandersnatch keys defining the Bandersnatch validator keys (kb) beginning in the next epoch.
type EpochMarker struct {
	Entropy        crypto.Hash
	TicketsEntropy crypto.Hash
	Keys           [common.NumberOfValidators]ValidatorKeys
}

type WinningTicketMarker [jamtime.TimeslotsPerEpoch]Ticket

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
