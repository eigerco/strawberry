//go:build integration

// Genesis state, block and keys adapted from: https://github.com/jam-duna/jamtestnet
package simulation

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"sort"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/eigerco/strawberry/internal/block"
	"github.com/eigerco/strawberry/internal/common"
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/jamtime"
	"github.com/eigerco/strawberry/internal/safrole"
	"github.com/eigerco/strawberry/internal/state"
	"github.com/eigerco/strawberry/internal/state/merkle"
	"github.com/eigerco/strawberry/internal/statetransition"
	"github.com/eigerco/strawberry/internal/store"
	"github.com/eigerco/strawberry/internal/testutils"
	jsonutils "github.com/eigerco/strawberry/internal/testutils/json"
	"github.com/eigerco/strawberry/internal/validator"
	"github.com/eigerco/strawberry/pkg/db/pebble"
)

func TestSimulateSAFROLE(t *testing.T) {
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

	// Gensesis block.
	data, err = os.ReadFile("genesis-block-tiny.json")
	require.NoError(t, err)
	var genesisSimBlock SimulationBlock
	err = json.Unmarshal(data, &genesisSimBlock)
	currentBlock := toBlock(t, genesisSimBlock)
	require.NoError(t, err)

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
	slotLeaderKey := crypto.BandersnatchPrivateKey{}
	slotLeaderName := ""

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

		nextEpoch := currentTimeslot.ToEpoch()
		previousEpoch := currentState.TimeslotIndex.ToEpoch()

		// Reset the ticket attempts at the start of each epoch.
		if currentTimeslot.IsFirstTimeslotInEpoch() {
			for k := range ticketAttempts {
				ticketAttempts[k] = 0
			}
		}

		// Find the slot leader.
		found := false
		for _, k := range keys {
			key := crypto.BandersnatchPrivateKey(testutils.MustFromHex(t, k.BandersnatchPrivate))
			ok, err := isSlotLeader(currentTimeslot, currentState, key)
			require.NoError(t, err)
			if ok {
				slotLeaderKey = key
				slotLeaderName = k.Name
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("slot leader not found")
		}

		require.NotEqual(t, slotLeaderKey, crypto.BandersnatchPrivateKey{})
		t.Logf("slot leader: %s", slotLeaderName)

		headerHash, err := currentBlock.Header.Hash()
		require.NoError(t, err)

		entropy := currentState.EntropyPool[2]
		pendingValidators := currentState.ValidatorState.SafroleState.NextValidators
		if nextEpoch > previousEpoch {
			pendingValidators = validator.NullifyOffenders(currentState.ValidatorState.QueuedValidators, currentState.PastJudgements.OffendingValidators)
			entropy = currentState.EntropyPool[1]
		}

		// Submit tickets if possible.
		ticketProofs := []block.TicketProof{}
		if currentTimeslot.IsTicketSubmissionPeriod() && !currentTimeslot.IsFirstTimeslotInEpoch() {
			// Pretty simple, loop over each validator and submit a ticket if they have enough attempts left.
			// We submit 3 tickets at a time for now.
			for _, key := range keys {
				if ticketAttempts[key.Name] < common.MaxTicketAttempts {
					attempt := ticketAttempts[key.Name]
					ticketProducerKey := crypto.BandersnatchPrivateKey(testutils.MustFromHex(t, key.BandersnatchPrivate))
					// TOOD this will need fancier logic too. Needs to use the right yk and eta depending on epoch change.
					ticketProof, err := state.CreateTicketProof(pendingValidators, entropy, ticketProducerKey, uint8(attempt))
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
		}

		newBlock, err := produceBlock(
			currentTimeslot,
			headerHash,
			currentState,
			trieDB,
			slotLeaderKey,
			ticketProofs,
		)
		require.NoError(t, err)

		t.Logf("block prior state root: %v", hex.EncodeToString(newBlock.Header.PriorStateRoot[:]))
		t.Logf("block parent hash: %v", hex.EncodeToString(newBlock.Header.ParentHash[:]))

		// Update state
		err = statetransition.UpdateState(
			currentState,
			newBlock,
			chainDB,
		)
		require.NoError(t, err)

		currentBlock = newBlock
	}
}

func isSlotLeader(timeslot jamtime.Timeslot, currentState *state.State, privateKey crypto.BandersnatchPrivateKey) (bool, error) {
	_, sealingKeys, sealingEntropy, _, err := nextSAFROLEState(currentState, timeslot)
	if err != nil {
		return false, err
	}

	return state.IsSlotLeader(timeslot, sealingKeys, sealingEntropy, privateKey)
}

// Produces and seals a block with potential tickets.
// TODO, move this to a better package an make it public when it's ready.
func produceBlock(
	timeslot jamtime.Timeslot,
	parentHash crypto.Hash,
	currentState *state.State,
	trie *store.Trie,
	privateKey crypto.BandersnatchPrivateKey,
	ticketProofs []block.TicketProof,
) (block.Block, error) {

	nextEpoch := timeslot.ToEpoch()
	previousTimeslot := currentState.TimeslotIndex
	previousEpoch := previousTimeslot.ToEpoch()
	isNewEpoch := nextEpoch > previousEpoch

	pendingValidators, sealingKeys, sealingEntropy, ticketEntropy, err := nextSAFROLEState(currentState, timeslot)
	if err != nil {
		return block.Block{}, err
	}

	extrinsics := block.Extrinsic{}

	ringCommitment, err := pendingValidators.RingCommitment()
	if err != nil {
		return block.Block{}, err
	}

	accumulator := currentState.ValidatorState.SafroleState.TicketAccumulator
	bestTicketProofs, err := filterTicketProofs(accumulator, ringCommitment, ticketEntropy, ticketProofs)
	if err != nil {
		return block.Block{}, err
	}

	extrinsics.ET.TicketProofs = bestTicketProofs

	rootHash, err := merkle.MerklizeState(*currentState, trie)
	if err != nil {
		return block.Block{}, err
	}

	extrinsicsHash, err := extrinsics.Hash()
	if err != nil {
		return block.Block{}, err
	}

	header := &block.Header{
		ParentHash:     parentHash,
		PriorStateRoot: rootHash,
		ExtrinsicHash:  extrinsicsHash,
		TimeSlotIndex:  timeslot,
	}

	// Generate the epoch marker.
	if isNewEpoch {
		header.EpochMarker = &block.EpochMarker{
			Entropy:        currentState.EntropyPool[0],
			TicketsEntropy: currentState.EntropyPool[1],
		}
		for i, vd := range pendingValidators {
			header.EpochMarker.Keys[i].Bandersnatch = vd.Bandersnatch
		}
	}

	// Generate the ticket marker.
	ticketAccumulatorFull := len(accumulator) == jamtime.TimeslotsPerEpoch
	if nextEpoch == previousEpoch &&
		timeslot.IsWinningTicketMarkerPeriod(previousTimeslot) &&
		ticketAccumulatorFull {
		winningTickets := safrole.OutsideInSequence(currentState.ValidatorState.SafroleState.TicketAccumulator)
		header.WinningTicketsMarker = (*block.WinningTicketMarker)(winningTickets)
	}

	// Now we can finally seal the block. Just need to use the right entropy, if it's an epoch change
	// we use eta_2, that will become eta_3, otherwise just eta_3.
	err = state.SealBlock(header, sealingKeys, sealingEntropy, privateKey)
	if err != nil {
		return block.Block{}, err
	}

	return block.Block{
		Header:    *header,
		Extrinsic: extrinsics,
	}, nil
}

// Filter ticket proofs from sumbitted ticket proofs. The idea here is to filter
// out any useless tickets that wouldn't end up being included, and also to
// ensure the ticket proofs are in the correcct order. TODO, this should be
// moved when ready, similar to produceBlock.
func filterTicketProofs(
	accumulator []block.Ticket,
	ringCommitment crypto.RingCommitment,
	entropy crypto.Hash,
	ticketProofs []block.TicketProof,
) ([]block.TicketProof, error) {

	// Create tickets from proofs and a mapping from ticket proof to ticket to
	// use later.
	proofToID := map[crypto.RingVrfSignature]crypto.BandersnatchOutputHash{}
	newTickets := []block.Ticket{}
	for _, tp := range ticketProofs {
		// TODO this will require some fancier logic.
		// will need the correct yk and eta depending on epoch change.
		outputHash, err := state.VerifyTicketProof(ringCommitment, entropy, tp)
		if err != nil {
			return nil, err
		}
		newTickets = append(newTickets, block.Ticket{
			Identifier: outputHash,
			EntryIndex: tp.EntryIndex,
		})
		proofToID[tp.Proof] = outputHash
	}

	// Combine new tickets with the existing accumulator.
	allTickets := make([]block.Ticket, len(accumulator)+len(newTickets))
	copy(allTickets, accumulator)
	copy(allTickets[len(accumulator):], newTickets)

	// Resort by identifier.
	sort.Slice(allTickets, func(i, j int) bool {
		return bytes.Compare(allTickets[i].Identifier[:], allTickets[j].Identifier[:]) < 0
	})

	// Drop older tickets, limiting the accumulator to |E|.
	if len(allTickets) > jamtime.TimeslotsPerEpoch {
		allTickets = allTickets[:jamtime.TimeslotsPerEpoch]
	}

	// Filter out any ticket proofs that are not in the accumulator now.
	existingIds := make(map[crypto.BandersnatchOutputHash]struct{}, len(allTickets))
	for _, ticket := range allTickets {
		existingIds[ticket.Identifier] = struct{}{}
	}
	bestTicketProofs := []block.TicketProof{}
	for _, tp := range ticketProofs {
		if _, ok := existingIds[proofToID[tp.Proof]]; ok {
			bestTicketProofs = append(bestTicketProofs, tp)
		}
	}

	// Sort ticket proofs by their output hash using the mapping from above.
	if len(bestTicketProofs) > 0 {
		sort.Slice(bestTicketProofs, func(i, j int) bool {
			hi := proofToID[bestTicketProofs[i].Proof]
			hj := proofToID[bestTicketProofs[j].Proof]
			return bytes.Compare(hi[:], hj[:]) < 0
		})
	}

	return bestTicketProofs, nil
}

// Determine the next components of the SAFROLE state. This mostly concerns an epoch change.
// If there's an epoch change then we can't use the current state as is, instead we need to figure out what the next
// state for the various SAFROLE components will become.
// If there's a new epoch then:
// - pendingValidators, ie y_k becomes the queued validators with offenders nullified.
// - sealingKeys become the outside in function applied to the current ticket accumulator, or else fallback.
// - sealingEntropy becomes eta_2, which becomes eta_3 in the next epoch.
// - ticketEntropy becomes eta_1, which becomes eta_2 in the next epoch.
func nextSAFROLEState(currentState *state.State, nextTimeslot jamtime.Timeslot) (
	pendingValidators safrole.ValidatorsData,
	sealingKeys safrole.SealingKeys,
	sealingEntropy crypto.Hash,
	ticketEntropy crypto.Hash,
	err error,
) {

	nextEpoch := nextTimeslot.ToEpoch()
	previousTimeslot := currentState.TimeslotIndex
	previousEpoch := previousTimeslot.ToEpoch()
	isNewEpoch := nextEpoch > previousEpoch
	accumulator := currentState.ValidatorState.SafroleState.TicketAccumulator
	ticketAccumulatorFull := len(accumulator) == jamtime.TimeslotsPerEpoch

	if isNewEpoch {
		pendingValidators = validator.NullifyOffenders(currentState.ValidatorState.QueuedValidators, currentState.PastJudgements.OffendingValidators)
		sealingEntropy = currentState.EntropyPool[2]
		ticketEntropy = currentState.EntropyPool[1]
		if nextEpoch == previousEpoch+jamtime.Epoch(1) &&
			!previousTimeslot.IsTicketSubmissionPeriod() &&
			ticketAccumulatorFull {
			// Ticket case.
			sealingTickets := safrole.OutsideInSequence(currentState.ValidatorState.SafroleState.TicketAccumulator)
			sealingKeys.Set(safrole.TicketsBodies(sealingTickets))
		} else {
			// Fallback case.
			// Here we need to use eta_1 which will become eta_2 in the next epoch.
			fallbackKeys, err := safrole.SelectFallbackKeys(currentState.EntropyPool[1], currentState.ValidatorState.SafroleState.NextValidators)
			if err != nil {
				return pendingValidators, sealingKeys, ticketEntropy, sealingEntropy, err
			}
			sealingKeys.Set(fallbackKeys)
		}
	} else {
		pendingValidators = currentState.ValidatorState.SafroleState.NextValidators
		sealingEntropy = currentState.EntropyPool[3]
		ticketEntropy = currentState.EntropyPool[2]
		sealingKeys = currentState.ValidatorState.SafroleState.SealingKeySeries
	}

	return pendingValidators, sealingKeys, sealingEntropy, ticketEntropy, nil
}

// Helper to covert a SimulationBlock to a Block.
func toBlock(t *testing.T, simBlock SimulationBlock) block.Block {

	b := block.Block{
		Header: block.Header{
			ParentHash:       crypto.Hash(testutils.MustFromHex(t, simBlock.Header.Parent)),
			PriorStateRoot:   crypto.Hash(testutils.MustFromHex(t, simBlock.Header.ParentStateRoot)),
			ExtrinsicHash:    crypto.Hash(testutils.MustFromHex(t, simBlock.Header.ExtrinsicHash)),
			TimeSlotIndex:    jamtime.Timeslot(simBlock.Header.Slot),
			BlockAuthorIndex: uint16(simBlock.Header.AuthorIndex),
		},
	}

	if simBlock.Header.EpochMark != nil {
		epochMark := &block.EpochMarker{
			Entropy:        crypto.Hash(testutils.MustFromHex(t, simBlock.Header.EpochMark.Entropy)),
			TicketsEntropy: crypto.Hash(testutils.MustFromHex(t, simBlock.Header.EpochMark.TicketsEntropy)),
		}

		for i, v := range simBlock.Header.EpochMark.Validators {
			epochMark.Keys[i].Bandersnatch = crypto.BandersnatchPublicKey(testutils.MustFromHex(t, v))
		}

		b.Header.EpochMarker = epochMark
	}

	return b
}

// Only these fields are needed for now. Extrinsics will be added as we need them.
type SimulationBlock struct {
	Header struct {
		Parent          string `json:"parent"`
		ParentStateRoot string `json:"parent_state_root"`
		ExtrinsicHash   string `json:"extrinsic_hash"`
		Slot            int    `json:"slot"`
		EpochMark       *struct {
			Entropy        string   `json:"entropy"`
			TicketsEntropy string   `json:"tickets_entropy"`
			Validators     []string `json:"validators"`
		} `json:"epoch_mark"`
		AuthorIndex   int    `json:"author_index"`
		EntropySource string `json:"entropy_source"`
		Seal          string `json:"seal"`
	} `json:"header"`
}

type ValidatorKeys struct {
	Name                string `json:"name"`
	Seed                string `json:"seed"`
	Ed25519Private      string `json:"ed25519_private"`
	Ed25519Public       string `json:"ed25519_public"`
	BandersnatchPrivate string `json:"bandersnatch_private"`
	BandersnatchPublic  string `json:"bandersnatch_public"`
	DnsAltName          string `json:"dns_alt_name"`
}
