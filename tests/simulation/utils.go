package simulation

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/eigerco/strawberry/internal/block"
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/crypto/bandersnatch"
	"github.com/eigerco/strawberry/internal/jamtime"
	"github.com/eigerco/strawberry/internal/state"
	"github.com/eigerco/strawberry/internal/state/merkle"
	"github.com/eigerco/strawberry/internal/statetransition"
	"github.com/eigerco/strawberry/internal/store"
)

// Figures out the current slot leader by checking each of the validator keys. Useful only for testing.
func FindSlotLeader(timeslot jamtime.Timeslot, currentState *state.State, keys []ValidatorKeys) (string, crypto.BandersnatchPrivateKey, error) {
	slotLeaderName := ""
	slotLeaderKey := crypto.BandersnatchPrivateKey{}
	// Find the slot leader.
	found := false
	for _, k := range keys {
		ok, err := IsSlotLeader(timeslot, currentState, k.BandersnatchPrivate)
		if err != nil {
			return "", slotLeaderKey, fmt.Errorf("error checking slot leader: %w", err)
		}
		if ok {
			slotLeaderName = k.Name
			slotLeaderKey = k.BandersnatchPrivate
			found = true
			break
		}
	}
	if !found {
		return "", slotLeaderKey, fmt.Errorf("slot leader not found")
	}

	return slotLeaderName, slotLeaderKey, nil
}

// Determines if the given private key is the slot leader for the given timeslot.
func IsSlotLeader(timeslot jamtime.Timeslot, currentState *state.State, privateKey crypto.BandersnatchPrivateKey) (bool, error) {
	validatorState, output, err := statetransition.NextSafroleState(currentState, timeslot, block.DisputeExtrinsic{})
	if err != nil {
		return false, err
	}

	return state.IsSlotLeader(timeslot, validatorState.SafroleState.SealingKeySeries, output.SealingEntropy, privateKey)
}

// Produces a block. This function will stabilize over time and eventually be
// moved into a node package.  Right now it can correctly package tickets but
// other extrinsics are just added to the block as is.
func ProduceBlock(
	timeslot jamtime.Timeslot,
	parentHash crypto.Hash,
	currentState *state.State,
	trie *store.Trie,
	privateKey crypto.BandersnatchPrivateKey,
	extrinsics block.Extrinsic,
) (block.Block, error) {

	validatorState, output, err := statetransition.NextSafroleState(currentState, timeslot, extrinsics.ED)
	if err != nil {
		return block.Block{}, err
	}

	bestTicketProofs, err := filterTicketProofs(
		validatorState.SafroleState.TicketAccumulator,
		validatorState.SafroleState.RingCommitment,
		output.TicketEntropy,
		extrinsics.ET.TicketProofs)
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

	var authorIndex uint16
	found := false
	authorPubKey, err := bandersnatch.Public(privateKey)
	if err != nil {
		return block.Block{}, err
	}

	for i, v := range validatorState.CurrentValidators {
		if v.Bandersnatch == authorPubKey {
			found = true
			authorIndex = uint16(i)
			break
		}
	}
	if !found {
		return block.Block{}, fmt.Errorf("author index not found in active validators")
	}

	offenders := []ed25519.PublicKey{}
	for _, c := range extrinsics.ED.Culprits {
		offenders = append(offenders, c.ValidatorEd25519PublicKey)
	}
	for _, f := range extrinsics.ED.Faults {
		offenders = append(offenders, f.ValidatorEd25519PublicKey)
	}

	header := &block.Header{
		ParentHash:           parentHash,
		PriorStateRoot:       rootHash,
		ExtrinsicHash:        extrinsicsHash,
		TimeSlotIndex:        timeslot,
		BlockAuthorIndex:     authorIndex,
		EpochMarker:          output.EpochMark,
		WinningTicketsMarker: output.WinningTicketMark,
		OffendersMarkers:     offenders,
	}

	err = state.SealBlock(header, validatorState.SafroleState.SealingKeySeries, output.SealingEntropy, privateKey)
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

// Stores validator keys for testing purposes.
type ValidatorKeys struct {
	Name                string                        `json:"name"`
	Seed                string                        `json:"seed"`
	Ed25519Private      ed25519.PrivateKey            `json:"ed25519_private"`
	Ed25519Public       ed25519.PublicKey             `json:"ed25519_public"`
	BandersnatchPrivate crypto.BandersnatchPrivateKey `json:"bandersnatch_private"`
	BandersnatchPublic  crypto.BandersnatchPublicKey  `json:"bandersnatch_public"`
	DnsAltName          string                        `json:"dns_alt_name"`
}

type ValidatorKeysEncoded struct {
	Name                string `json:"name"`
	Seed                string `json:"seed"`
	Ed25519Private      string `json:"ed25519_private"`
	Ed25519Public       string `json:"ed25519_public"`
	BandersnatchPrivate string `json:"bandersnatch_private"`
	BandersnatchPublic  string `json:"bandersnatch_public"`
	DnsAltName          string `json:"dns_alt_name"`
}

func (v *ValidatorKeys) UnmarshalJSON(data []byte) error {
	var vke ValidatorKeysEncoded
	err := json.Unmarshal(data, &vke)
	if err != nil {
		return err
	}
	bandersnatchPrivate, err := hexToBytes(vke.BandersnatchPrivate)
	if err != nil {
		return err
	}
	bandersnatchPublic, err := hexToBytes(vke.BandersnatchPublic)
	if err != nil {
		return err
	}
	ed25519Seed, err := hexToBytes(vke.Ed25519Private)
	if err != nil {
		return err
	}
	ed25519Public, err := hexToBytes(vke.Ed25519Public)
	if err != nil {
		return err
	}

	// Convert seed to full private key (seed + public key)
	var ed25519Private ed25519.PrivateKey
	if len(ed25519Seed) == 32 {
		// If it's a seed, generate the full private key
		ed25519Private = ed25519.NewKeyFromSeed(ed25519Seed)
	} else if len(ed25519Seed) == 64 {
		// If it's already a full private key, use it as is
		ed25519Private = ed25519.PrivateKey(ed25519Seed)
	} else {
		return fmt.Errorf("invalid ed25519 private key length: %d", len(ed25519Seed))
	}

	*v = ValidatorKeys{
		Name:                vke.Name,
		Seed:                vke.Seed,
		Ed25519Private:      ed25519Private,
		Ed25519Public:       ed25519.PublicKey(ed25519Public),
		BandersnatchPrivate: crypto.BandersnatchPrivateKey(bandersnatchPrivate),
		BandersnatchPublic:  crypto.BandersnatchPublicKey(bandersnatchPublic),
		DnsAltName:          vke.DnsAltName,
	}

	return nil
}

func (v *ValidatorKeys) MarshalJSON() ([]byte, error) {
	return json.Marshal(ValidatorKeysEncoded{
		Name:                v.Name,
		Seed:                v.Seed,
		Ed25519Private:      bytesToHex(v.Ed25519Private),
		Ed25519Public:       bytesToHex(v.Ed25519Public),
		BandersnatchPrivate: bytesToHex(v.BandersnatchPrivate[:]),
		BandersnatchPublic:  bytesToHex(v.BandersnatchPublic[:]),
		DnsAltName:          v.DnsAltName,
	})
}

func hexToBytes(s string) ([]byte, error) {
	b, err := hex.DecodeString(strings.TrimPrefix(s, "0x"))
	if err != nil {
		return nil, err
	}
	return b, nil
}

func bytesToHex(b []byte) string {
	return "0x" + hex.EncodeToString(b)
}
