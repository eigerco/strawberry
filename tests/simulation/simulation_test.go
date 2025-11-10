//go:build tiny

// Genesis state, block and keys adapted from: https://github.com/jam-duna/jamtestnet
package simulation

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/eigerco/strawberry/internal/block"
	"github.com/eigerco/strawberry/internal/common"
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/jamtime"
	"github.com/eigerco/strawberry/internal/state"
	"github.com/eigerco/strawberry/internal/statetransition"
	"github.com/eigerco/strawberry/internal/store"
	jsonutils "github.com/eigerco/strawberry/internal/testutils/json"
	"github.com/eigerco/strawberry/internal/validator"
	"github.com/eigerco/strawberry/pkg/db/pebble"
)

func TestSimulateSAFROLE(t *testing.T) {
	t.Skip("deprecated")
	data, err := os.ReadFile("keys.json")
	require.NoError(t, err)

	// Genesis validator keys.
	var keys []ValidatorKeys
	err = json.Unmarshal(data, &keys)
	require.NoError(t, err)

	// Genesis state.
	data, err = os.ReadFile("genesis-state-tiny.json")
	require.NoError(t, err)
	var currentState *state.State
	restoredState := jsonutils.RestoreStateSnapshot(data)
	currentState = &restoredState

	// Genesis block.
	data, err = os.ReadFile("genesis-block-tiny.json")
	require.NoError(t, err)
	currentBlock := jsonutils.RestoreBlockSnapshot(data)

	// Trie DB for merklization.
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

	initialTimeslot := 12
	endTimeslot := initialTimeslot + 24

	// Stores the number of attempts for a given validator name.
	ticketAttempts := map[string]int{}
	for _, k := range keys {
		ticketAttempts[k.Name] = 0
	}

	// This is the main loop that:
	// - Finds the slot leader key.
	// - Produces and seals a new block using that key.
	// - Updates the safrole state using that block to get the next state.
	// - Does some verifications on the new state.
	// - Repeats.
	for timeslot := initialTimeslot; timeslot < endTimeslot; timeslot++ {
		t.Logf("timeslot: %d", timeslot)
		currentTimeslot := jamtime.Timeslot(timeslot)

		// Reset the ticket attempts at the start of each epoch.
		if currentTimeslot.IsFirstTimeslotInEpoch() {
			for k := range ticketAttempts {
				ticketAttempts[k] = 0
			}
		}

		// Find the slot leader.
		slotLeaderName, slotLeaderKey, err := FindSlotLeader(
			currentTimeslot,
			currentState,
			keys,
		)
		require.NoError(t, err)
		require.NotEqual(t, slotLeaderKey, crypto.BandersnatchPrivateKey{})
		t.Logf("slot leader: %s", slotLeaderName)

		headerHash, err := currentBlock.Header.Hash()
		require.NoError(t, err)

		// Submit tickets if possible.
		ticketProofs := submitTickets(t, keys, currentState, currentTimeslot, ticketAttempts)

		extrinsics := block.Extrinsic{
			ET: block.TicketExtrinsic{
				TicketProofs: ticketProofs,
			},
		}

		newBlock, err := ProduceBlock(
			currentTimeslot,
			headerHash,
			currentState,
			trieDB,
			slotLeaderKey,
			extrinsics,
		)
		require.NoError(t, err)

		t.Logf("block prior state root: %v", hex.EncodeToString(newBlock.Header.PriorStateRoot[:]))
		t.Logf("block parent hash: %v", hex.EncodeToString(newBlock.Header.ParentHash[:]))

		// Update state.
		err = statetransition.UpdateState(
			currentState,
			newBlock,
			chainDB,
			trieDB,
		)
		require.NoError(t, err)

		currentBlock = newBlock
	}
}

func submitTickets(
	t *testing.T,
	keys []ValidatorKeys,
	currentState *state.State,
	currentTimeslot jamtime.Timeslot,
	ticketAttempts map[string]int,
) []block.TicketProof {
	nextEpoch := currentTimeslot.ToEpoch()
	previousEpoch := currentState.TimeslotIndex.ToEpoch()

	entropy := currentState.EntropyPool[2]
	pendingValidators := currentState.ValidatorState.SafroleState.NextValidators
	if nextEpoch > previousEpoch {
		pendingValidators, _ = validator.NullifyOffenders(currentState.ValidatorState.QueuedValidators, currentState.PastJudgements.OffendingValidators)
		entropy = currentState.EntropyPool[1]
	}

	ticketProofs := []block.TicketProof{}
	for _, key := range keys {
		if ticketAttempts[key.Name] < common.MaxTicketAttemptsPerValidator {
			attempt := ticketAttempts[key.Name]
			// TODO this will need fancier logic too. Needs to use the right yk and eta depending on epoch change.
			ticketProof, err := state.CreateTicketProof(pendingValidators, entropy, key.BandersnatchPrivate, uint8(attempt))
			require.NoError(t, err)
			t.Logf("submitted ticket, name: %v, attempt: %v, proof: %v", key.Name, attempt,
				hex.EncodeToString(ticketProof.Proof[:])[:10]+"...")
			ticketProofs = append(ticketProofs, ticketProof)
			ticketAttempts[key.Name]++
		}
		if len(ticketProofs) == common.MaxTicketExtrinsicSize {
			break
		}
	}

	return ticketProofs
}
