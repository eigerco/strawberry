package block

import (
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/time"
)

// Header as defined in the section 5 in the paper
type Header struct {
	ParentHash           crypto.Hash                     // Hp
	PriorStateRoot       crypto.Hash                     // Hr
	ExtrinsicHash        crypto.Hash                     // Hx
	TimeSlotIndex        time.Timeslot                   // Ht
	EpochMarker          []crypto.Hash                   // He
	WinningTicketsMarker [time.TimeslotsPerEpoch]*Ticket // Hw
	JudgementsMarkers    []crypto.Hash                   // Hj
	BlockAuthorKey       []byte                          // Hk
	VRFSignature         []byte                          // Hv
	BlockSealSignature   []byte                          // Hs
}
