package block

import (
	"crypto/ed25519"
	"errors"
	"fmt"

	"github.com/eigerco/strawberry/pkg/db"
	"github.com/eigerco/strawberry/pkg/db/pebble"

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

// EpochMarker consists of epoch randomness and a sequence of
// Bandersnatch keys defining the Bandersnatch validator keys (kb) beginning in the next epoch.
type EpochMarker struct {
	Entropy        crypto.Hash
	TicketsEntropy crypto.Hash
	Keys           [common.NumberOfValidators]crypto.BandersnatchPublicKey
}

type WinningTicketMarker [jamtime.TimeslotsPerEpoch]Ticket

// AncestorStoreSingleton the in memory store for headers that need to be kept for 24 hours
// TODO: Add 24 hours TTL
var AncestorStoreSingleton = NewAncestorStore()

// AncestorStore manages blockchain header storage using KVStore as the backend
type AncestorStore struct {
	store db.KVStore
}

// NewAncestorStore creates a new in-memory ancestor store using KVStore
func NewAncestorStore() *AncestorStore {
	store, err := pebble.NewKVStore()
	if err != nil {
		panic(fmt.Errorf("failed to initialize store: %w", err))
	}

	return &AncestorStore{
		store: store,
	}
}

// StoreHeader stores a header in the database
func (a *AncestorStore) StoreHeader(header Header) error {
	encodedHeader, err := jam.Marshal(header)
	if err != nil {
		return fmt.Errorf("failed to marshal header: %w", err)
	}
	hash := crypto.HashData(encodedHeader)

	if err := a.store.Put(hash[:], encodedHeader); err != nil {
		return fmt.Errorf("failed to store header: %w", err)
	}

	return nil
}

// GetAncestor retrieves the parent header for the given header
func (a *AncestorStore) GetAncestor(header Header) (Header, error) {
	encodedHeader, err := a.store.Get(header.ParentHash[:])
	if err != nil {
		if errors.Is(err, pebble.ErrNotFound) {
			return Header{}, nil
		}
		return Header{}, fmt.Errorf("failed to get ancestor: %w", err)
	}

	var ancestorHeader Header
	if err := jam.Unmarshal(encodedHeader, &ancestorHeader); err != nil {
		return Header{}, fmt.Errorf("failed to unmarshal header: %w", err)
	}

	return ancestorHeader, nil
}

// FindAncestor finds a header that matches the given predicate
func (a *AncestorStore) FindAncestor(fn func(header Header) bool) (Header, error) {
	iter, err := a.store.NewIterator(nil, nil)
	if err != nil {
		return Header{}, fmt.Errorf("failed to create iterator: %w", err)
	}
	defer func(iter db.Iterator) {
		err := iter.Close()
		if err != nil {
			panic(fmt.Errorf("failed to close iterator: %w", err))
		}
	}(iter)

	for valid := iter.Next(); valid; valid = iter.Next() {
		value, err := iter.Value()
		if err != nil {
			return Header{}, fmt.Errorf("failed to get value: %w", err)
		}

		var header Header
		if err := jam.Unmarshal(value, &header); err != nil {
			return Header{}, fmt.Errorf("failed to unmarshal header: %w", err)
		}

		if fn(header) {
			return header, nil
		}
	}

	return Header{}, nil
}

// Close closes the underlying store
func (a *AncestorStore) Close() error {
	return a.store.Close()
}
