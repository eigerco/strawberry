//go:build integration

package simulation

import (
	"os"
	"testing"

	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/state"
	"github.com/eigerco/strawberry/internal/statetransition"
	"github.com/eigerco/strawberry/internal/store"
	jsonutils "github.com/eigerco/strawberry/internal/testutils/json"
	"github.com/eigerco/strawberry/pkg/db/pebble"
	"github.com/stretchr/testify/require"
)

// TestSimulateTicket tests a happy path for submitting some ticket proofs.  It
// tests an important edge case where we submit ticket proofs in the first block
// of a new epoch. This means we would have had to correctly predict what the
// next SAFROLE state would be in order to use the right entropy and ring
// commitment. We check this by verifying the tickets again using the post
// state, and making sure they all end up in the accumulator which would have
// been reset as part of the epoch transition.
func TestSimulateTicket(t *testing.T) {
	// Prestate
	data, err := os.ReadFile("ticket_prestate_001.json")
	require.NoError(t, err)
	var currentState *state.State
	restoredPreState := jsonutils.RestoreStateSnapshot(data)
	currentState = &restoredPreState

	preActivityStats := currentState.ActivityStatistics

	// Block
	data, err = os.ReadFile("ticket_block_001.json")
	require.NoError(t, err)
	testBlock := jsonutils.RestoreBlockSnapshot(data)

	db, err := pebble.NewKVStore()
	require.NoError(t, err)
	defer func() {
		err := db.Close()
		require.NoError(t, err, "failed to close db")
	}()

	trieDB := store.NewTrie(db)
	require.NoError(t, err)

	chainDB := store.NewChain(db)
	require.NoError(t, err)

	// Update state
	err = statetransition.UpdateState(
		currentState,
		testBlock,
		chainDB,
		trieDB,
	)
	require.NoError(t, err)

	// Check that each ticket proof has made it's way into the post state ticket
	// accumulator.  The accumulator has just been reset, so it should have the
	// length of the tickets extrinsic.
	require.Equal(t, len(currentState.ValidatorState.SafroleState.TicketAccumulator), len(testBlock.Extrinsic.ET.TicketProofs))

	postStateTicketIDs := map[crypto.BandersnatchOutputHash]struct{}{}

	for _, ticket := range currentState.ValidatorState.SafroleState.TicketAccumulator {
		postStateTicketIDs[ticket.Identifier] = struct{}{}
	}

	for _, ticketProof := range testBlock.Extrinsic.ET.TicketProofs {
		ticketID, err := state.VerifyTicketProof(currentState.ValidatorState.SafroleState.RingCommitment, currentState.EntropyPool[2], ticketProof)
		require.NoError(t, err)
		require.Contains(t, postStateTicketIDs, ticketID)
	}

	// Check that validator activity stats were rotated correctly on epoch
	// change. Current should become last.
	require.Equal(t, preActivityStats.ValidatorsCurrent, currentState.ActivityStatistics.ValidatorsLast)

	// Our validator should have 1 block and 3 tickets in this new epoch.
	require.Equal(t, uint32(1), currentState.ActivityStatistics.ValidatorsCurrent[testBlock.Header.BlockAuthorIndex].NumOfBlocks)
	require.Equal(t, uint32(3), currentState.ActivityStatistics.ValidatorsCurrent[testBlock.Header.BlockAuthorIndex].NumOfTickets)
}
