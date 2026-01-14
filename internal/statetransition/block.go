package statetransition

import (
	"errors"
	"fmt"

	"github.com/eigerco/strawberry/internal/block"
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/jamtime"
	"github.com/eigerco/strawberry/internal/state"
	"github.com/eigerco/strawberry/internal/state/merkle"
	"github.com/eigerco/strawberry/internal/store"
	"github.com/eigerco/strawberry/internal/validator"
)

// CheckTimeliness indicates whether to check if the block timeslot is in the future
// TODO: make this a config
var CheckTimeliness bool

// VerifyBlockHeaderBasic verifies header fields which are verifiable with just
// the prior state:
// - The timeslot
// - The prior state root
// - The extrinsic hash
// The trie database must be passed in produce the merkle root of the state and store trie nodes.
// GP v0.7.0
func VerifyBlockHeaderBasic(priorState *state.State, block block.Block, trie *store.Trie) error {
	// H_T · P ≤ T  Equation 5.7 (partial)
	if CheckTimeliness && block.Header.TimeSlotIndex.IsInFuture() {
		return errors.New("timeslot is in the future")
	}
	// Timeslot must be greater than parent's. Equation 5.7 (the rest)
	// P(H)_T < H_T
	if priorState.TimeslotIndex >= block.Header.TimeSlotIndex {
		return errors.New("timeslot must be greater than the prior state's timeslot")
	}

	// State root validation. Equation 5.8
	//  H_R ≡ M_σ(σ)
	expectedPriorStateRoot, err := merkle.MerklizeState(*priorState, trie)
	if err != nil {
		return fmt.Errorf("failed to merklize state: %w", err)
	}
	if block.Header.PriorStateRoot != expectedPriorStateRoot {
		return fmt.Errorf("invalid prior state root: %x", expectedPriorStateRoot)
	}

	// Check extrinsic hash. Equation 5.4
	// H_X ≡ H(E(H#(a)))
	expectedExtrinsicsHash, err := block.Extrinsic.Hash()
	if err != nil {
		return fmt.Errorf("failed to hash extrinsics: %w", err)
	}
	if block.Header.ExtrinsicHash != expectedExtrinsicsHash {
		return fmt.Errorf("invalid extrinsics hash: %x", expectedExtrinsicsHash)
	}

	return nil
}

// VerifyBlockHeaderBasicFromStateRoot verifies header fields using a cached prior state root.
// This does not store trie nodes.
func VerifyBlockHeaderBasicFromStateRoot(priorStateRoot crypto.Hash, priorTimeslot jamtime.Timeslot, block block.Block) error {
	// H_T · P ≤ T  Equation 5.7 (partial)
	if CheckTimeliness && block.Header.TimeSlotIndex.IsInFuture() {
		return errors.New("timeslot is in the future")
	}
	// Timeslot must be greater than parent's. Equation 5.7 (the rest)
	// P(H)_T < H_T
	if priorTimeslot >= block.Header.TimeSlotIndex {
		return errors.New("timeslot must be greater than the prior state's timeslot")
	}

	// State root validation. Equation 5.8
	//  H_R ≡ M_σ(σ)
	if block.Header.PriorStateRoot != priorStateRoot {
		return fmt.Errorf("invalid prior state root: %x", priorStateRoot)
	}

	// Check extrinsic hash. Equation 5.4
	// H_X ≡ H(E(H#(a)))
	expectedExtrinsicsHash, err := block.Extrinsic.Hash()
	if err != nil {
		return fmt.Errorf("failed to hash extrinsics: %w", err)
	}
	if block.Header.ExtrinsicHash != expectedExtrinsicsHash {
		return fmt.Errorf("invalid extrinsics hash: %x", expectedExtrinsicsHash)
	}

	return nil
}

// VerifyBlockHeaderSafrole verifies the SAFROLE related fields of the block header:
// - The epoch marker
// - The winning ticket marker.
// - The block seal and vrf signatures.
// The validatorState should be the posterior SAFROLE state, this function is expected to be used after UpdateSafroleState has been run.
// GP v0.7.0
func VerifyBlockHeaderSafrole(validatorState validator.ValidatorState, output SafroleOutput, block block.Block) error {
	// Check the epoch marker. Equation 6.27
	// H_E ≡ (η_0, η_1, [(k_b, k_e) | k <− γ′_P ]) if e′ > e,  ∅ otherwise.
	if output.EpochMark == nil {
		// The expected epoch marker is not set, so the header epoch marker
		// shouldn't be either.
		if block.Header.EpochMarker != nil {
			return errors.New("epoch marker is set, but should be nil")
		}
	} else {
		// The expected epoch marker is set, so the header epoch marker should
		// be set and be valid.
		if block.Header.EpochMarker == nil {
			return errors.New("epoch marker is nil, but should be set")
		}

		if block.Header.EpochMarker.Entropy != output.EpochMark.Entropy {
			return errors.New("epoch marker entropy is invalid")
		}

		if block.Header.EpochMarker.TicketsEntropy != output.EpochMark.TicketsEntropy {
			return errors.New("epoch marker tickets entropy is invalid")
		}

		for i, vk := range output.EpochMark.Keys {
			if block.Header.EpochMarker.Keys[i].Bandersnatch != vk.Bandersnatch {
				return errors.New("epoch marker bandersnatch key is invalid")
			}
			if !block.Header.EpochMarker.Keys[i].Ed25519.Equal(vk.Ed25519) {
				return errors.New("epoch marker ed25519 key is invalid")
			}
		}
	}

	// Check winning ticket marker. Equation 6.28
	// H_W = Z(γ_A) if e′ = e ∧ m < Y ≤ m′ ∧ |γ_A| = E, ∅ otherwise
	if output.WinningTicketMark == nil {
		// The expected winning ticket marker is not set, so the header winning
		// ticket marker shouldn't be set either.
		if block.Header.WinningTicketsMarker != nil {
			return errors.New("winning ticket marker is set, but should be nil")
		}
	} else {
		// The expected winning ticket marker is set, so the header winning
		// ticket marker should be set and valid.
		if block.Header.WinningTicketsMarker == nil {
			return errors.New("winning ticket marker is nil, but should be set")
		}
		if *block.Header.WinningTicketsMarker != *output.WinningTicketMark {
			return errors.New("winning ticket marker is invalid")
		}

	}

	// Verify the block seal and VRF signatures. Equations 6.15 - 6.20
	// Equations for this are more complex, refer directly to the GP.
	ok, err := state.VerifyBlockSeal(&block.Header, validatorState.SafroleState.SealingKeySeries, validatorState.CurrentValidators, output.SealingEntropy)
	if err != nil {
		return fmt.Errorf("failed to verify block seal: %w", err)
	}
	if !ok {
		return errors.New("block seal or vrf signature is invalid")
	}

	return nil
}
