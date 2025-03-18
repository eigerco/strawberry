//go:build integration

// Genesis state, block and keys adapted from: https://github.com/jam-duna/jamtestnet
package simulation

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/eigerco/strawberry/internal/block"
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/crypto/bandersnatch"
	"github.com/eigerco/strawberry/internal/jamtime"
	"github.com/eigerco/strawberry/internal/merkle/trie"
	"github.com/eigerco/strawberry/internal/safrole"
	"github.com/eigerco/strawberry/internal/state"
	"github.com/eigerco/strawberry/internal/state/merkle"
	"github.com/eigerco/strawberry/internal/statetransition"
	"github.com/eigerco/strawberry/internal/testutils"
	"github.com/eigerco/strawberry/internal/validator"
	"github.com/stretchr/testify/require"
)

func TestSimulateSAFROLE(t *testing.T) {
	data, err := os.ReadFile("keys.json")
	require.NoError(t, err)

	// Genesis validator keys.
	var keys []ValidatorKeys
	err = json.Unmarshal(data, &keys)
	require.NoError(t, err)
	data, err = os.ReadFile("genesis-state-tiny.json")
	require.NoError(t, err)

	// Genesis state.
	var simState SimulationState
	err = json.Unmarshal(data, &simState)
	require.NoError(t, err)
	currentState := toState(t, simState)
	data, err = os.ReadFile("genesis-block-tiny.json")
	require.NoError(t, err)

	// Gensesis block.
	var genesisSimBlock SimulationBlock
	err = json.Unmarshal(data, &genesisSimBlock)
	currentBlock := toBlock(t, genesisSimBlock)
	require.NoError(t, err)

	// Trie DB for merklization.
	trie, err := trie.NewDB()
	require.NoError(t, err)
	defer trie.Close()

	initialTimeslot := 12
	endTimeslot := initialTimeslot + 24
	slotLeaderKey := crypto.BandersnatchPrivateKey{}
	slotLeaderName := ""

	// This is the main loop that:
	// - Finds the slot leader key.
	// - Produces and seals a new block using that key.
	// - Updates the safrole state using that block to get the next state.
	// - Does some verifications on the new state.
	// - Repeats.
	for timeslot := initialTimeslot; timeslot < endTimeslot; timeslot++ {
		t.Logf("timeslot: %d", timeslot)
		currentTimeslot := jamtime.Timeslot(timeslot)

		// Find the slot leader.
		for _, k := range keys {
			key := crypto.BandersnatchPrivateKey(testutils.MustFromHex(t, k.BandersnatchPrivate))
			ok, err := state.IsSlotLeader(currentTimeslot, currentState, key)
			require.NoError(t, err)
			if ok {
				slotLeaderKey = key
				slotLeaderName = k.Name
				break
			}
		}

		require.NotEqual(t, slotLeaderKey, crypto.BandersnatchPrivateKey{})
		t.Logf("slot leader: %s", slotLeaderName)

		headerHash, err := currentBlock.Header.Hash()
		require.NoError(t, err)

		newBlock, err := produceBlock(
			currentTimeslot,
			headerHash,
			currentState,
			trie,
			slotLeaderKey,
		)
		require.NoError(t, err)

		t.Logf("block prior state root: %v", hex.EncodeToString(newBlock.Header.PriorStateRoot[:]))
		t.Logf("block parent hash: %v", hex.EncodeToString(newBlock.Header.ParentHash[:]))

		// Update the SAFROLE state.
		entropy, err := bandersnatch.OutputHash(newBlock.Header.VRFSignature)
		require.NoError(t, err)

		safroleInput := statetransition.SafroleInput{
			TimeSlot: currentTimeslot,
			Entropy:  entropy,
		}

		newEntropyPool, newValidatorState, safroleOutput, err := statetransition.UpdateSafroleState(
			safroleInput,
			currentState.TimeslotIndex,
			currentState.EntropyPool,
			currentState.ValidatorState,
		)
		require.NoError(t, err)

		// Verify that the epoch marker is correct.
		require.Equal(t, safroleOutput.EpochMark, newBlock.Header.EpochMarker)

		// Update the current state and block.
		currentState.TimeslotIndex = currentTimeslot
		currentState.EntropyPool = newEntropyPool
		currentState.ValidatorState = newValidatorState

		currentBlock = newBlock
	}
}

// Produces and seals an empty block. TODO, move this to a better package an
// make it public when it's ready.
func produceBlock(
	timeslot jamtime.Timeslot,
	parentHash crypto.Hash,
	currentState *state.State,
	trie *trie.DB,
	key crypto.BandersnatchPrivateKey,
) (block.Block, error) {
	rootHash, err := merkle.MerklizeState(*currentState, trie)
	if err != nil {
		return block.Block{}, err
	}

	nextEpoch := timeslot.ToEpoch()
	previousEpoch := currentState.TimeslotIndex.ToEpoch()

	header := &block.Header{
		ParentHash:     parentHash,
		PriorStateRoot: rootHash,
		ExtrinsicHash:  crypto.Hash{}, // TODO
		TimeSlotIndex:  timeslot,
	}

	if nextEpoch > previousEpoch {
		header.EpochMarker = &block.EpochMarker{
			Entropy:        currentState.EntropyPool[0],
			TicketsEntropy: currentState.EntropyPool[1],
		}
		for i, vd := range currentState.ValidatorState.SafroleState.NextValidators {
			header.EpochMarker.Keys[i] = vd.Bandersnatch
		}
	}

	state.SealBlock(header, currentState, key)

	return block.Block{
		Header: *header,
	}, nil
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
			epochMark.Keys[i] = crypto.BandersnatchPublicKey(testutils.MustFromHex(t, v))
		}

		b.Header.EpochMarker = epochMark
	}

	return b
}

// Helper too convert a SimulationState to a State.
func toState(t *testing.T, s SimulationState) *state.State {
	currentValidators := safrole.ValidatorsData{}
	for i, vd := range s.Kappa {
		currentValidators[i] = &crypto.ValidatorKey{
			Bandersnatch: crypto.BandersnatchPublicKey(testutils.MustFromHex(t, vd.Bandersnatch)),
			Ed25519:      ed25519.PublicKey(testutils.MustFromHex(t, vd.Ed25519)),
			Bls:          crypto.BlsKey(testutils.MustFromHex(t, vd.Bls)),
			Metadata:     crypto.MetadataKey(testutils.MustFromHex(t, vd.Metadata)),
		}
	}

	archivedValidators := safrole.ValidatorsData{}
	for i, vd := range s.Lambda {
		archivedValidators[i] = &crypto.ValidatorKey{
			Bandersnatch: crypto.BandersnatchPublicKey(testutils.MustFromHex(t, vd.Bandersnatch)),
			Ed25519:      ed25519.PublicKey(testutils.MustFromHex(t, vd.Ed25519)),
			Bls:          crypto.BlsKey(testutils.MustFromHex(t, vd.Bls)),
			Metadata:     crypto.MetadataKey(testutils.MustFromHex(t, vd.Metadata)),
		}
	}

	queuedValidators := safrole.ValidatorsData{}
	for i, vd := range s.Iota {
		queuedValidators[i] = &crypto.ValidatorKey{
			Bandersnatch: crypto.BandersnatchPublicKey(testutils.MustFromHex(t, vd.Bandersnatch)),
			Ed25519:      ed25519.PublicKey(testutils.MustFromHex(t, vd.Ed25519)),
			Bls:          crypto.BlsKey(testutils.MustFromHex(t, vd.Bls)),
			Metadata:     crypto.MetadataKey(testutils.MustFromHex(t, vd.Metadata)),
		}
	}

	nextValidators := safrole.ValidatorsData{}
	for i, vd := range s.Gamma.GammaK {
		nextValidators[i] = &crypto.ValidatorKey{
			Bandersnatch: crypto.BandersnatchPublicKey(testutils.MustFromHex(t, vd.Bandersnatch)),
			Ed25519:      ed25519.PublicKey(testutils.MustFromHex(t, vd.Ed25519)),
			Bls:          crypto.BlsKey(testutils.MustFromHex(t, vd.Bls)),
			Metadata:     crypto.MetadataKey(testutils.MustFromHex(t, vd.Metadata)),
		}
	}

	ticketAccumulator := make([]block.Ticket, len(s.Gamma.GammaA))
	for i, tb := range s.Gamma.GammaA {
		ticketAccumulator[i] = block.Ticket{
			Identifier: crypto.BandersnatchOutputHash(testutils.MustFromHex(t, tb.ID)),
			EntryIndex: tb.Attempt,
		}
	}

	ticketOrKeys := safrole.TicketAccumulator{}
	if len(s.Gamma.GammaS.Keys) > 0 {
		keys := crypto.EpochKeys{}
		for i, k := range s.Gamma.GammaS.Keys {
			keys[i] = crypto.BandersnatchPublicKey(testutils.MustFromHex(t, k))
		}
		ticketOrKeys.SetValue(keys)
	} else if len(s.Gamma.GammaS.Tickets) > 0 {
		tickets := safrole.TicketsBodies{}
		for i, tb := range s.Gamma.GammaS.Tickets {
			tickets[i] = block.Ticket{
				Identifier: crypto.BandersnatchOutputHash(testutils.MustFromHex(t, tb.ID)),
				EntryIndex: tb.Attempt,
			}
		}
		ticketOrKeys.SetValue(tickets)
	} else {
		t.Fatal("missing tickets or keys for gamma_s")
	}

	entropyPool := state.EntropyPool{}
	for i, e := range s.Eta {
		entropyPool[i] = crypto.Hash(testutils.MustFromHex(t, e))
	}

	return &state.State{
		TimeslotIndex: jamtime.Timeslot(s.Tau),
		EntropyPool:   entropyPool,
		ValidatorState: validator.ValidatorState{
			CurrentValidators:  currentValidators,
			ArchivedValidators: archivedValidators,
			QueuedValidators:   queuedValidators,
			SafroleState: safrole.State{
				NextValidators:    nextValidators,
				TicketAccumulator: ticketAccumulator,
				SealingKeySeries:  ticketOrKeys,
				RingCommitment:    crypto.RingCommitment(testutils.MustFromHex(t, s.Gamma.GammaZ)),
			},
		},
	}
}

// Only these fields are needed for now. To be expanded as our test add more of the state.
type SimulationState struct {
	Gamma struct {
		GammaK []struct {
			Bandersnatch string `json:"bandersnatch"`
			Ed25519      string `json:"ed25519"`
			Bls          string `json:"bls"`
			Metadata     string `json:"metadata"`
		} `json:"gamma_k"`
		GammaZ string `json:"gamma_z"`
		GammaS struct {
			Keys    []string `json:"keys"`
			Tickets []struct {
				ID      string `json:"id"`
				Attempt uint8  `json:"attempt"`
			} `json:"tickets"`
		} `json:"gamma_s"`
		GammaA []struct {
			ID      string `json:"id"`
			Attempt uint8  `json:"attempt"`
		} `json:"gamma_a"`
	} `json:"gamma"`
	Eta  []string `json:"eta"`
	Iota []struct {
		Bandersnatch string `json:"bandersnatch"`
		Ed25519      string `json:"ed25519"`
		Bls          string `json:"bls"`
		Metadata     string `json:"metadata"`
	} `json:"iota"`
	Kappa []struct {
		Bandersnatch string `json:"bandersnatch"`
		Ed25519      string `json:"ed25519"`
		Bls          string `json:"bls"`
		Metadata     string `json:"metadata"`
	} `json:"kappa"`
	Lambda []struct {
		Bandersnatch string `json:"bandersnatch"`
		Ed25519      string `json:"ed25519"`
		Bls          string `json:"bls"`
		Metadata     string `json:"metadata"`
	} `json:"lambda"`
	Tau int `json:"tau"`
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
