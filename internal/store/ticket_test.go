package store

import (
	"testing"

	"github.com/eigerco/strawberry/internal/block"
	"github.com/eigerco/strawberry/internal/testutils"
	"github.com/eigerco/strawberry/pkg/db/pebble"
	"github.com/stretchr/testify/require"
)

func TestPutGetTicket(t *testing.T) {
	db, err := pebble.NewKVStore()
	require.NoError(t, err)
	defer func() {
		err := db.Close()
		require.NoError(t, err, "failed to close db")
	}()
	ticketStore := NewTicket(db)
	hash := testutils.RandomBandersnatchOutputHash(t)
	expectedTicket := block.TicketProof{
		EntryIndex: 0,
		Proof:      [block.TicketProofSize]byte{1, 2, 3, 4},
	}
	err = ticketStore.PutTicket(1, expectedTicket, hash)
	require.NoError(t, err, "failed to put ticket")
	ticket, err := ticketStore.GetTicket(1, hash)
	require.NoError(t, err, "failed to get ticket")
	require.Equal(t, expectedTicket, ticket, "ticket mismatch")
}

func TestDeleteTicket(t *testing.T) {
	db, err := pebble.NewKVStore()
	require.NoError(t, err)
	defer func() {
		err := db.Close()
		require.NoError(t, err, "failed to close db")
	}()
	ticketStore := NewTicket(db)
	hash := testutils.RandomBandersnatchOutputHash(t)
	expectedTicket := block.TicketProof{
		EntryIndex: 0,
		Proof:      [block.TicketProofSize]byte{1, 2, 3, 4},
	}
	err = ticketStore.PutTicket(1, expectedTicket, hash)
	require.NoError(t, err, "failed to put ticket")
	err = ticketStore.DeleteTicket(1, hash)
	require.NoError(t, err, "failed to delete ticket")
	ticket, err := ticketStore.GetTicket(1, hash)
	require.Error(t, err, "expected error when getting deleted ticket")
	require.Equal(t, block.TicketProof{}, ticket, "ticket should be empty after deletion")
}

func TestGetTicketsForEpoch(t *testing.T) {
	db, err := pebble.NewKVStore()
	require.NoError(t, err)
	defer func() {
		err := db.Close()
		require.NoError(t, err, "failed to close db")
	}()
	ticketStore := NewTicket(db)

	// Create test data for multiple epochs
	epoch1 := uint32(1)
	epoch2 := uint32(2)

	// Add multiple tickets for epoch 1
	hash1 := testutils.RandomBandersnatchOutputHash(t)
	hash2 := testutils.RandomBandersnatchOutputHash(t)
	hash3 := testutils.RandomBandersnatchOutputHash(t)

	ticket1 := block.TicketProof{
		EntryIndex: 0,
		Proof:      [block.TicketProofSize]byte{1, 2, 3, 4},
	}
	ticket2 := block.TicketProof{
		EntryIndex: 1,
		Proof:      [block.TicketProofSize]byte{5, 6, 7, 8},
	}
	ticket3 := block.TicketProof{
		EntryIndex: 2,
		Proof:      [block.TicketProofSize]byte{9, 10, 11, 12},
	}

	// Add tickets for epoch 1
	err = ticketStore.PutTicket(epoch1, ticket1, hash1)
	require.NoError(t, err, "failed to put ticket1")
	err = ticketStore.PutTicket(epoch1, ticket2, hash2)
	require.NoError(t, err, "failed to put ticket2")

	// Add ticket for epoch 2 (should not be returned when querying epoch 1)
	err = ticketStore.PutTicket(epoch2, ticket3, hash3)
	require.NoError(t, err, "failed to put ticket3")

	// Get tickets for epoch 1
	tickets, err := ticketStore.GetTicketsForEpoch(epoch1)
	require.NoError(t, err, "failed to get tickets for epoch 1")
	require.Len(t, tickets, 2, "expected 2 tickets for epoch 1")

	require.Contains(t, tickets, ticket1, "ticket1 should be present")
	require.Contains(t, tickets, ticket2, "ticket2 should be present")
	require.NotContains(t, tickets, ticket3, "ticket3 should not be present in epoch 1")

	// Get tickets for epoch 2
	tickets2, err := ticketStore.GetTicketsForEpoch(epoch2)
	require.NoError(t, err, "failed to get tickets for epoch 2")
	require.Len(t, tickets2, 1, "expected 1 ticket for epoch 2")
	require.Contains(t, tickets2, ticket3, "ticket3 data mismatch")

	// Get tickets for non-existent epoch
	ticketsEmpty, err := ticketStore.GetTicketsForEpoch(999)
	require.NoError(t, err, "failed to get tickets for non-existent epoch")
	require.Len(t, ticketsEmpty, 0, "expected 0 tickets for non-existent epoch")
}

func TestDeleteTicketsForEpoch(t *testing.T) {
	db, err := pebble.NewKVStore()
	require.NoError(t, err)
	defer func() {
		err := db.Close()
		require.NoError(t, err, "failed to close db")
	}()
	ticketStore := NewTicket(db)

	// Create test data for multiple epochs
	epoch1 := uint32(1)
	epoch2 := uint32(2)

	// Add multiple tickets for epoch 1
	hash1 := testutils.RandomBandersnatchOutputHash(t)
	hash2 := testutils.RandomBandersnatchOutputHash(t)
	hash3 := testutils.RandomBandersnatchOutputHash(t)

	ticket1 := block.TicketProof{
		EntryIndex: 0,
		Proof:      [block.TicketProofSize]byte{1, 2, 3, 4},
	}
	ticket2 := block.TicketProof{
		EntryIndex: 1,
		Proof:      [block.TicketProofSize]byte{5, 6, 7, 8},
	}
	ticket3 := block.TicketProof{
		EntryIndex: 2,
		Proof:      [block.TicketProofSize]byte{9, 10, 11, 12},
	}

	// Add tickets for epoch 1
	err = ticketStore.PutTicket(epoch1, ticket1, hash1)
	require.NoError(t, err, "failed to put ticket1")
	err = ticketStore.PutTicket(epoch1, ticket2, hash2)
	require.NoError(t, err, "failed to put ticket2")

	// Add ticket for epoch 2 (should remain after deleting epoch 1)
	err = ticketStore.PutTicket(epoch2, ticket3, hash3)
	require.NoError(t, err, "failed to put ticket3")

	// Verify tickets exist before deletion
	tickets1Before, err := ticketStore.GetTicketsForEpoch(epoch1)
	require.NoError(t, err, "failed to get tickets for epoch 1 before deletion")
	require.Len(t, tickets1Before, 2, "expected 2 tickets for epoch 1 before deletion")

	tickets2Before, err := ticketStore.GetTicketsForEpoch(epoch2)
	require.NoError(t, err, "failed to get tickets for epoch 2 before deletion")
	require.Len(t, tickets2Before, 1, "expected 1 ticket for epoch 2 before deletion")

	// Delete all tickets for epoch 1
	err = ticketStore.DeleteTicketsForEpoch(epoch1)
	require.NoError(t, err, "failed to delete tickets for epoch 1")

	// Verify epoch 1 tickets are deleted
	tickets1After, err := ticketStore.GetTicketsForEpoch(epoch1)
	require.NoError(t, err, "failed to get tickets for epoch 1 after deletion")
	require.Len(t, tickets1After, 0, "expected 0 tickets for epoch 1 after deletion")

	// Verify epoch 2 tickets are unaffected
	tickets2After, err := ticketStore.GetTicketsForEpoch(epoch2)
	require.NoError(t, err, "failed to get tickets for epoch 2 after deletion")
	require.Len(t, tickets2After, 1, "expected 1 ticket for epoch 2 after deletion")
	require.Equal(t, ticket3, tickets2After[0], "epoch 2 ticket should be unchanged")

	// Test deleting from empty epoch (should not error)
	err = ticketStore.DeleteTicketsForEpoch(999)
	require.NoError(t, err, "deleting from empty epoch should not error")

	// Test deleting already deleted epoch (should not error)
	err = ticketStore.DeleteTicketsForEpoch(epoch1)
	require.NoError(t, err, "deleting already deleted epoch should not error")
}
