package block

import (
	"crypto/ed25519"
	"github.com/eigerco/strawberry/internal/common"
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/jamtime"
	"github.com/eigerco/strawberry/pkg/serialization"
	"github.com/eigerco/strawberry/pkg/serialization/codec"
	"sync"
)

// Header as defined in the section 5 in the paper
type Header struct {
	ParentHash           crypto.Hash                        // Hp
	PriorStateRoot       crypto.Hash                        // Hr
	ExtrinsicHash        crypto.Hash                        // Hx
	TimeSlotIndex        jamtime.Timeslot                   // Ht
	EpochMarker          *EpochMarker                       // He
	WinningTicketsMarker *[jamtime.TimeslotsPerEpoch]Ticket // Hw
	OffendersMarkers     []ed25519.PublicKey                // Ho, the culprit's and fault's public keys
	BlockAuthorIndex     uint16                             // Hi
	VRFSignature         crypto.BandersnatchSignature       // Hv
	BlockSealSignature   crypto.BandersnatchSignature       // Hs
}

// EpochMarker consists of epoch randomness and a sequence of
// Bandersnatch keys defining the Bandersnatch validator keys (kb) beginning in the next epoch.
type EpochMarker struct {
	Entropy crypto.Hash
	Keys    [common.NumberOfValidators]crypto.BandersnatchPublicKey
}

// AncestorStoreSingleton the in memory store for headers that need to be kept for 24 hours
// TODO replace with pebble
var AncestorStoreSingleton = &AncestorStore{
	ancestorSet: make(map[crypto.Hash]*Header),
	mu:          sync.RWMutex{},
}

type AncestorStore struct {
	ancestorSet map[crypto.Hash]*Header
	mu          sync.RWMutex
}

func (a *AncestorStore) StoreHeader(header *Header) error {
	encodedHeader, err := serialization.NewSerializer(codec.NewJamCodec()).Encode(header)
	if err != nil {
		return err
	}
	hash := crypto.HashData(encodedHeader)
	a.mu.Lock()
	defer a.mu.Unlock()
	a.ancestorSet[hash] = header
	return nil
}

func (a *AncestorStore) GetAncestor(header *Header) *Header {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.ancestorSet[header.ParentHash]
}

func (a *AncestorStore) FindAncestor(fn func(header *Header) bool) *Header {
	a.mu.RLock()
	defer a.mu.RUnlock()
	for _, h := range a.ancestorSet {
		if fn(h) {
			return h
		}
	}
	return nil
}
