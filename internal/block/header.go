package block

import (
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/jamtime"
)

// Header as defined in the section 5 in the paper
type Header struct {
	ParentHash           crypto.Hash                        // Hp
	PriorStateRoot       crypto.Hash                        // Hr
	ExtrinsicHash        crypto.Hash                        // Hx
	TimeSlotIndex        jamtime.Timeslot                   // Ht
	EpochMarker          *EpochMarker                       // He
	WinningTicketsMarker *[jamtime.TimeslotsPerEpoch]Ticket // Hw
	OffendersMarkers     []crypto.Ed25519PublicKey          // Ho, the culprit's and fault's public keys
	BlockAuthorIndex     uint16                             // Hi
	VRFSignature         crypto.BandersnatchSignature       // Hv
	BlockSealSignature   crypto.BandersnatchSignature       // Hs
}

// EpochMarker consists of epoch randomness and a sequence of
// Bandersnatch keys defining the Bandersnatch validator keys (kb) beginning in the next epoch.
type EpochMarker struct {
	Entropy crypto.Hash
	Keys    [NumberOfValidators]crypto.BandersnatchPublicKey
}
