package store

import (
	"encoding/binary"
	"fmt"
	"log"

	"github.com/eigerco/strawberry/internal/block"
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/pkg/db"
	"github.com/eigerco/strawberry/pkg/serialization/codec/jam"
)

type Ticket struct {
	db.KVStore
}

// NewTicket creates a new ticket store using KVStore
func NewTicket(db db.KVStore) *Ticket {
	return &Ticket{KVStore: db}
}

// PutTicket stores a ticket in the ticket store
func (t *Ticket) PutTicket(epoch uint32, ticket block.TicketProof, hash crypto.BandersnatchOutputHash) error {
	bytes, err := jam.Marshal(ticket)
	if err != nil {
		return fmt.Errorf("marshal ticket: %w", err)
	}
	if err := t.Put(makeTicketKey(prefixTicket, epoch, hash), bytes); err != nil {
		return fmt.Errorf("put ticket: %w", err)
	}
	return nil
}

// GetTicket retrieves a ticket from the ticket store
func (t *Ticket) GetTicket(epoch uint32, hash crypto.BandersnatchOutputHash) (block.TicketProof, error) {
	key := makeTicketKey(prefixTicket, epoch, hash)
	bytes, err := t.Get(key)
	if err != nil {
		return block.TicketProof{}, fmt.Errorf("get ticket: %w", err)
	}
	var ticket block.TicketProof
	if err := jam.Unmarshal(bytes, &ticket); err != nil {
		return block.TicketProof{}, fmt.Errorf("unmarshal ticket: %w", err)
	}
	return ticket, nil
}

// DeleteTicket removes a ticket from the ticket store
func (t *Ticket) DeleteTicket(epoch uint32, hash crypto.BandersnatchOutputHash) error {
	key := makeTicketKey(prefixTicket, epoch, hash)
	if err := t.Delete(key); err != nil {
		return fmt.Errorf("delete ticket: %w", err)
	}
	return nil
}

// GetTicketsForEpoch retrieves all tickets for a given epoch
func (t *Ticket) GetTicketsForEpoch(epoch uint32) ([]block.TicketProof, error) {
	// Create start and end keys for the epoch range
	startKey := make([]byte, 5) // prefix(1) + epoch(4)
	startKey[0] = prefixTicket
	binary.LittleEndian.PutUint32(startKey[1:], epoch)

	endKey := make([]byte, 5)
	endKey[0] = prefixTicket
	binary.LittleEndian.PutUint32(endKey[1:], epoch+1)

	iter, err := t.NewIterator(startKey, endKey)
	if err != nil {
		return nil, fmt.Errorf("create iterator: %w", err)
	}
	defer iter.Close() //nolint:errcheck // TODO: handle error

	var tickets []block.TicketProof

	for iter.Next() {
		if !iter.Valid() {
			break
		}

		value, err := iter.Value()
		if err != nil {
			return nil, fmt.Errorf("get iterator value: %w", err)
		}

		var ticket block.TicketProof
		if err := jam.Unmarshal(value, &ticket); err != nil {
			return nil, fmt.Errorf("unmarshal ticket: %w", err)
		}

		tickets = append(tickets, ticket)
	}

	return tickets, nil
}

// DeleteTicketsForEpoch removes all tickets for a given epoch
func (t *Ticket) DeleteTicketsForEpoch(epoch uint32) error {
	// Create start and end keys for the epoch range
	startKey := make([]byte, 5) // prefix(1) + epoch(4)
	startKey[0] = prefixTicket
	binary.LittleEndian.PutUint32(startKey[1:], epoch)

	endKey := make([]byte, 5)
	endKey[0] = prefixTicket
	binary.LittleEndian.PutUint32(endKey[1:], epoch+1)

	iter, err := t.NewIterator(startKey, endKey)
	if err != nil {
		return fmt.Errorf("create iterator: %w", err)
	}
	defer func() {
		if err := iter.Close(); err != nil {
			log.Printf("error closing iterator: %v", err)
		}
	}()

	// Use batch for atomic deletion of all keys
	batch := t.NewBatch()
	defer func() {
		if err := batch.Close(); err != nil {
			log.Printf("error closing batch: %v", err)
		}
	}()

	for iter.Next() {
		if !iter.Valid() {
			break
		}

		key := iter.Key()
		if err := batch.Delete(key); err != nil {
			return fmt.Errorf("batch delete key: %w", err)
		}
	}

	// Commit all deletions atomically
	if err := batch.Commit(); err != nil {
		return fmt.Errorf("commit batch: %w", err)
	}

	return nil
}

// makeTicketKey creates a key for the ticket store
// The key format is: [prefix(1 byte)][epoch(8 bytes)][hash(32 bytes)]
func makeTicketKey(prefix byte, epoch uint32, hash crypto.BandersnatchOutputHash) []byte {
	key := make([]byte, 1+4+len(hash))
	key[0] = prefix
	binary.LittleEndian.PutUint32(key[1:], epoch)
	copy(key[5:], hash[:])
	return key
}
