//go:build integration

package integration_test

import (
	"crypto/ed25519"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/eigerco/strawberry/internal/block"
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/jamtime"
	"github.com/eigerco/strawberry/internal/safrole"
	"github.com/eigerco/strawberry/internal/state"
	"github.com/eigerco/strawberry/internal/statetransition"
	"github.com/eigerco/strawberry/internal/testutils"
	"github.com/eigerco/strawberry/internal/validator"

	"github.com/stretchr/testify/require"
)

func TestSafrole(t *testing.T) {
	testFiles := []string{
		// Progress by one slot.
		// Randomness accumulator is updated.
		"vectors/safrole/enact-epoch-change-with-no-tickets-1.json",

		//Progress from slot X to slot X.
		//Timeslot must be strictly monotonic.
		"vectors/safrole/enact-epoch-change-with-no-tickets-2.json",

		// Progress from a slot at the begin of the epoch to a slot in the epoch's tail.
		// Tickets mark is not generated (no enough tickets).
		"vectors/safrole/enact-epoch-change-with-no-tickets-3.json",

		// Progress from epoch's tail to next epoch.
		// Authorities and entropies are rotated. Epoch mark is generated.
		"vectors/safrole/enact-epoch-change-with-no-tickets-4.json",

		// Progress skipping epochs with a full tickets accumulator.
		// Tickets mark is not generated. Accumulated tickets discarded. Fallback method enacted.
		"vectors/safrole/skip-epochs-1.json",

		// Progress to next epoch by skipping epochs tail with a full tickets accumulator.
		// Tickets mark has no chance to be generated. Accumulated tickets discarded. Fallback method enacted.
		"vectors/safrole/skip-epoch-tail-1.json",

		// Submit an extrinsic with a bad ticket attempt number.
		"vectors/safrole/publish-tickets-no-mark-1.json",

		// Submit good tickets extrinsic from some authorities.
		"vectors/safrole/publish-tickets-no-mark-2.json",

		// Submit one ticket already recorded in the state.
		"vectors/safrole/publish-tickets-no-mark-3.json",

		// Submit tickets in bad order.
		"vectors/safrole/publish-tickets-no-mark-4.json",

		// Submit tickets with bad ring proof.
		"vectors/safrole/publish-tickets-no-mark-5.json",

		// Submit some tickets.
		"vectors/safrole/publish-tickets-no-mark-6.json",

		// Submit tickets when epoch's lottery is over.
		"vectors/safrole/publish-tickets-no-mark-7.json",

		// Progress into epoch tail, closing the epoch's lottery.
		// No enough tickets, thus no tickets mark is generated.
		"vectors/safrole/publish-tickets-no-mark-8.json",

		// Progress into next epoch with no enough tickets.
		// Accumulated tickets are discarded. Epoch mark generated. Fallback method enacted.
		"vectors/safrole/publish-tickets-no-mark-9.json",

		// Publish some tickets with an almost full tickets accumulator.
		// Tickets accumulator is not full yet. No ticket is dropped from accumulator.
		"vectors/safrole/publish-tickets-with-mark-1.json",

		// Publish some tickets filling the accumulator.
		// Two old tickets are removed from the accumulator.
		"vectors/safrole/publish-tickets-with-mark-2.json",

		// Publish some tickets with a full accumulator.
		// Some old ticket are removed to make space for new ones.
		"vectors/safrole/publish-tickets-with-mark-3.json",

		// With a full accumulator, conclude the lottery.
		// Tickets mark is generated.
		"vectors/safrole/publish-tickets-with-mark-4.json",

		// With a published tickets mark, progress into next epoch.
		// Epoch mark is generated. Tickets are enacted.
		"vectors/safrole/publish-tickets-with-mark-5.json",

		// On epoch change we recompute the ring commitment.
		// One of the keys to be used is invalidated (zeroed out) because it belongs to the (posterior) offenders list.
		// One of the keys is just invalid (i.e. it can't be decoded into a valid Bandersnatch point).
		// Both the invalid keys are replaced with the padding point during ring commitment computation.
		"vectors/safrole/enact-epoch-change-with-padding-1.json",

		// Custom vector for publishing tickets in the first slot of a new
		// epoch. In this case we should be verifying this using the updated
		// entropy pool and ring commitment for the current epoch, not the
		// previous state values.
		"vectors/safrole/custom-publish-ticket-first-slot-new-epoch.json",
	}

	for _, tf := range testFiles {
		t.Run(filepath.Base(tf), func(t *testing.T) {
			file, err := os.ReadFile(tf)
			require.NoError(t, err)

			var tv SafroleTestVector
			err = json.Unmarshal(file, &tv)
			require.NoError(t, err)

			// Construct the SafroleInput from the test vector's input.
			tickets := make([]block.TicketProof, len(tv.Input.Extrinsic))
			for i, te := range tv.Input.Extrinsic {
				tickets[i] = block.TicketProof{
					EntryIndex: te.Attempt,
					Proof:      crypto.RingVrfSignature(testutils.MustFromHex(t, te.Signature)),
				}
			}

			offenders := make([]ed25519.PublicKey, len(tv.PreState.PostOffenders))
			for i, po := range tv.PreState.PostOffenders {
				offenders[i] = ed25519.PublicKey(testutils.MustFromHex(t, po))
			}

			input := statetransition.SafroleInput{
				TimeSlot: jamtime.Timeslot(tv.Input.Slot),
				Tickets:  tickets,
				Entropy:  crypto.BandersnatchOutputHash(testutils.MustFromHex(t, tv.Input.Entropy)),
			}

			preEntropyPool := toEntropyPool(t, tv.PreState)
			preValidatorState := toValidatorState(t, tv.PreState)

			// Update the SAFROLE state.
			postEntropyPool, postValidatorState, output, err := statetransition.UpdateSafroleState(input,
				jamtime.Timeslot(tv.PreState.Tau),
				preEntropyPool,
				preValidatorState,
				offenders,
			)
			if tv.Output.Err != "" {
				// There was an output error in the test vector, so we should produce a matching error.
				require.EqualError(t, err, strings.ReplaceAll(tv.Output.Err, "_", " "))
			} else {
				require.NoError(t, err)
			}

			expectedOutput := tv.Output.Ok
			if expectedOutput != nil {
				// Check epoch marker.
				if expectedOutput.EpochMark != nil {
					expectedEpochMarker := &block.EpochMarker{}
					expectedEpochMarker.Entropy = crypto.Hash(testutils.MustFromHex(t, expectedOutput.EpochMark.Entropy))
					expectedEpochMarker.TicketsEntropy = crypto.Hash(testutils.MustFromHex(t, expectedOutput.EpochMark.TicketsEntropy))
					for i, v := range expectedOutput.EpochMark.Validators {
						expectedEpochMarker.Keys[i].Bandersnatch = crypto.BandersnatchPublicKey(testutils.MustFromHex(t, v.Bandersnatch))
					}
					require.Equal(t, output.EpochMark, expectedEpochMarker)
				}

				// Check winning ticket marker.
				if len(expectedOutput.TicketsMark) != 0 {
					expectedWinningTicketMarker := &block.WinningTicketMarker{}
					for i, ticket := range expectedOutput.TicketsMark {
						expectedWinningTicketMarker[i] = block.Ticket{
							Identifier: crypto.BandersnatchOutputHash(testutils.MustFromHex(t, ticket.ID)),
							EntryIndex: ticket.Attempt,
						}
					}
					require.Equal(t, output.WinningTicketMark, expectedWinningTicketMarker)
				}
			}
			// Decode the expected state from the test vectors.
			expectedPostEntropyPool := toEntropyPool(t, tv.PostState)
			expectedPostValidatorState := toValidatorState(t, tv.PostState)

			require.Equal(t, expectedPostEntropyPool, postEntropyPool)
			// TODO - figure out how to get less crazy test output. Look into
			// using go-cmp rather.
			require.Equal(t, expectedPostValidatorState, postValidatorState)
		})
	}
}

// Helper to construct the validator state from the test vector's state.
func toValidatorState(t *testing.T, s SafroleTestVectorState) validator.ValidatorState {
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
	for i, vd := range s.GammaK {
		nextValidators[i] = &crypto.ValidatorKey{
			Bandersnatch: crypto.BandersnatchPublicKey(testutils.MustFromHex(t, vd.Bandersnatch)),
			Ed25519:      ed25519.PublicKey(testutils.MustFromHex(t, vd.Ed25519)),
			Bls:          crypto.BlsKey(testutils.MustFromHex(t, vd.Bls)),
			Metadata:     crypto.MetadataKey(testutils.MustFromHex(t, vd.Metadata)),
		}
	}

	ticketAccumulator := make([]block.Ticket, len(s.GammaA))
	for i, tb := range s.GammaA {
		ticketAccumulator[i] = block.Ticket{
			Identifier: crypto.BandersnatchOutputHash(testutils.MustFromHex(t, tb.ID)),
			EntryIndex: tb.Attempt,
		}
	}

	ticketOrKeys := safrole.TicketAccumulator{}
	if len(s.GammaS.Keys) > 0 {
		keys := crypto.EpochKeys{}
		for i, k := range s.GammaS.Keys {
			keys[i] = crypto.BandersnatchPublicKey(testutils.MustFromHex(t, k))
		}
		ticketOrKeys.SetValue(keys)
	} else if len(s.GammaS.Tickets) > 0 {
		tickets := safrole.TicketsBodies{}
		for i, tb := range s.GammaS.Tickets {
			tickets[i] = block.Ticket{
				Identifier: crypto.BandersnatchOutputHash(testutils.MustFromHex(t, tb.ID)),
				EntryIndex: tb.Attempt,
			}
		}
		ticketOrKeys.SetValue(tickets)
	} else {
		t.Fatal("missing tickets or keys for gamma_s")
	}

	return validator.ValidatorState{
		CurrentValidators:  currentValidators,
		ArchivedValidators: archivedValidators,
		QueuedValidators:   queuedValidators,
		SafroleState: safrole.State{
			NextValidators:    nextValidators,
			TicketAccumulator: ticketAccumulator,
			SealingKeySeries:  ticketOrKeys,
			RingCommitment:    crypto.RingCommitment(testutils.MustFromHex(t, s.GammaZ)),
		},
	}
}

// Helper to construct the entropy pool from the test vector's entropy pool.
func toEntropyPool(t *testing.T, s SafroleTestVectorState) state.EntropyPool {
	entropyPool := state.EntropyPool{}
	for i, e := range s.Eta {
		entropyPool[i] = crypto.Hash(testutils.MustFromHex(t, e))
	}

	return entropyPool
}

// Data structures for serializing SAFROLE test vectors.

type SafroleTestVectorTicketBody struct {
	ID      string `json:"id"`
	Attempt uint8  `json:"attempt"`
}

type SafroleTestVectorTicketsOrKeys struct {
	Tickets []SafroleTestVectorTicketBody `json:"tickets,omitempty"`
	Keys    []string                      `json:"keys,omitempty"`
}

type SafroleTestVectorValidatorData struct {
	Bandersnatch string `json:"bandersnatch"`
	Ed25519      string `json:"ed25519"`
	Bls          string `json:"bls"`
	Metadata     string `json:"metadata"`
}

type SafroleTestVectorTicketEnvelope struct {
	Attempt   uint8  `json:"attempt"`
	Signature string `json:"signature"`
}

type SafroleTestVectorEpochMark struct {
	Entropy        string                                 `json:"entropy"`
	TicketsEntropy string                                 `json:"tickets_entropy"`
	Validators     []SafroleTestVectorEpochMarkValidators `json:"validators"`
}

type SafroleTestVectorEpochMarkValidators struct {
	Bandersnatch string `json:"bandersnatch"`
	Ed25519      string `json:"ed25519"`
}

type SafroleTestVectorOutputMarks struct {
	EpochMark   *SafroleTestVectorEpochMark   `json:"epoch_mark,omitempty"`
	TicketsMark []SafroleTestVectorTicketBody `json:"tickets_mark,omitempty"`
}

type SafroleTestVectorState struct {
	Tau           uint32                           `json:"tau"`
	Eta           [4]string                        `json:"eta"`
	Lambda        []SafroleTestVectorValidatorData `json:"lambda"`
	Kappa         []SafroleTestVectorValidatorData `json:"kappa"`
	GammaK        []SafroleTestVectorValidatorData `json:"gamma_k"`
	Iota          []SafroleTestVectorValidatorData `json:"iota"`
	GammaA        []SafroleTestVectorTicketBody    `json:"gamma_a"`
	GammaS        SafroleTestVectorTicketsOrKeys   `json:"gamma_s"`
	GammaZ        string                           `json:"gamma_z"`
	PostOffenders []string                         `json:"post_offenders"`
}

type SafroleTestVectorInput struct {
	Slot      uint32                            `json:"slot"`
	Entropy   string                            `json:"entropy"`
	Extrinsic []SafroleTestVectorTicketEnvelope `json:"extrinsic"`
}

type SafroleTestVectorOutput struct {
	Ok  *SafroleTestVectorOutputMarks `json:"ok,omitempty"`
	Err string                        `json:"err,omitempty"`
}

type SafroleTestVector struct {
	Input     SafroleTestVectorInput  `json:"input"`
	PreState  SafroleTestVectorState  `json:"pre_state"`
	Output    SafroleTestVectorOutput `json:"output"`
	PostState SafroleTestVectorState  `json:"post_state"`
}
