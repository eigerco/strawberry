package block

import (
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/time"
)

const NumberOfValidators uint16 = 1023

// Header as defined in the section 5 in the paper
type Header struct {
	ParentHash           crypto.Hash                     // Hp
	PriorStateRoot       crypto.Hash                     // Hr
	ExtrinsicHash        crypto.Hash                     // Hx
	TimeSlotIndex        time.Timeslot                   // Ht
	EpochMarker          *EpochMarker                    // He
	WinningTicketsMarker [time.TimeslotsPerEpoch]*Ticket // Hw
	Verdicts             []crypto.Hash                   // Hj
	OffendersMarkers     []crypto.Ed25519PublicKey       // Ho, the culprit's and fault's public keys
	BlockAuthorIndex     uint16                          // Hi
	VRFSignature         crypto.BandersnatchSignature    // Hv
	BlockSealSignature   crypto.BandersnatchSignature    // Hs
}

// EpochMarker consists of epoch randomness and a sequence of
// Bandersnatch keys defining the Bandersnatch validator keys (kb) beginning in the next epoch.
type EpochMarker struct {
	Keys    [NumberOfValidators]crypto.BandersnatchPublicKey
	Entropy crypto.Hash
}
