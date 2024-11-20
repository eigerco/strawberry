package block

import (
	"crypto/ed25519"
	"github.com/eigerco/strawberry/internal/jamtime"
	"testing"

	"github.com/eigerco/strawberry/internal/common"
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/testutils"
	"github.com/eigerco/strawberry/pkg/serialization/codec/jam"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_HeaderEncodeDecode(t *testing.T) {
	h := Header{
		ParentHash:     testutils.RandomHash(t),
		PriorStateRoot: testutils.RandomHash(t),
		ExtrinsicHash:  testutils.RandomHash(t),
		TimeSlotIndex:  123,
		EpochMarker: &EpochMarker{
			Keys: [common.NumberOfValidators]crypto.BandersnatchPublicKey{
				testutils.RandomBandersnatchPublicKey(t),
				testutils.RandomBandersnatchPublicKey(t),
			},
			Entropy: testutils.RandomHash(t),
		},
		WinningTicketsMarker: &WinningTicketMarker{
			Ticket{
				Identifier: testutils.RandomBandersnatchOutputHash(t),
				EntryIndex: 111,
			}, Ticket{
				Identifier: testutils.RandomBandersnatchOutputHash(t),
				EntryIndex: 222,
			}},
		OffendersMarkers: []ed25519.PublicKey{
			testutils.RandomED25519PublicKey(t),
		},
		BlockAuthorIndex:   1,
		VRFSignature:       testutils.RandomBandersnatchSignature(t),
		BlockSealSignature: testutils.RandomBandersnatchSignature(t),
	}
	bb, err := jam.Marshal(h)
	require.NoError(t, err)

	h2 := Header{}
	err = jam.Unmarshal(bb, &h2)
	require.NoError(t, err)

	assert.Equal(t, h, h2)
}

func TestNewAncestorStore(t *testing.T) {
	store := NewAncestorStore()
	defer store.Close()

	assert.NotEmpty(t, store.store)
}

func createTestHeader(parentHash crypto.Hash, slot jamtime.Timeslot) Header {
	return Header{
		ParentHash:    parentHash,
		TimeSlotIndex: slot,
		// Other fields can be left at zero values for testing
	}
}

func TestStoreAndGetHeader(t *testing.T) {
	store := NewAncestorStore()
	defer store.Close()

	// Create a parent header with a zero ParentHash (genesis block)
	parentHeader := Header{
		ParentHash:    crypto.Hash{}, // Genesis block has no parent
		TimeSlotIndex: jamtime.Timeslot(1),
	}

	// Store the parent header
	err := store.StoreHeader(parentHeader)
	require.NoError(t, err)

	// Calculate the hash of the parent header
	encodedParentHeader, err := jam.Marshal(parentHeader)
	require.NoError(t, err)
	parentHeaderHash := crypto.HashData(encodedParentHeader)

	// Create a child header referencing the parent header
	childHeader := Header{
		ParentHash:    parentHeaderHash,
		TimeSlotIndex: parentHeader.TimeSlotIndex + 1,
	}

	// Store the child header
	err = store.StoreHeader(childHeader)
	require.NoError(t, err)

	// Retrieve the ancestor (parent header) of the child header
	ancestorHeader, err := store.GetAncestor(childHeader)
	require.NoError(t, err)
	require.NotEmpty(t, ancestorHeader, "Ancestor should be found")

	// Verify that the retrieved ancestor matches the original parent header
	assert.Equal(t, parentHeader.ParentHash, ancestorHeader.ParentHash, "ParentHash should match")
	assert.Equal(t, parentHeader.TimeSlotIndex, ancestorHeader.TimeSlotIndex, "TimeSlotIndex should match")
}

func TestGetNonExistentAncestor(t *testing.T) {
	store := NewAncestorStore()
	defer store.Close()

	header := Header{
		ParentHash: crypto.Hash{1, 2, 3}, // This hash doesn't exist in store
	}

	// Try to get a non-existent ancestor
	retrieved, err := store.GetAncestor(header)
	require.NoError(t, err)
	assert.Empty(t, retrieved)
}

func TestFindAncestor(t *testing.T) {
	store := NewAncestorStore()
	defer store.Close()

	// Store test headers
	headers := []Header{
		createTestHeader(crypto.Hash{1}, 1),
		createTestHeader(crypto.Hash{2}, 2),
		createTestHeader(crypto.Hash{3}, 3),
	}

	for _, h := range headers {
		err := store.StoreHeader(h)
		require.NoError(t, err)
	}

	testCases := []struct {
		name       string
		predicate  func(Header) bool
		expectSlot jamtime.Timeslot
		shouldFind bool
	}{
		{
			name: "Find by specific timeslot",
			predicate: func(h Header) bool {
				return h.TimeSlotIndex == 2
			},
			expectSlot: 2,
			shouldFind: true,
		},
		{
			name: "Find non-existent timeslot",
			predicate: func(h Header) bool {
				return h.TimeSlotIndex == 99
			},
			shouldFind: false,
		},
		{
			name: "Find by parent hash",
			predicate: func(h Header) bool {
				return h.ParentHash == crypto.Hash{2}
			},
			expectSlot: 2,
			shouldFind: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			found, err := store.FindAncestor(tc.predicate)
			require.NoError(t, err)

			if tc.shouldFind {
				require.NotEmpty(t, found)
				assert.Equal(t, tc.expectSlot, found.TimeSlotIndex)
			} else {
				assert.Empty(t, found)
			}
		})
	}
}
