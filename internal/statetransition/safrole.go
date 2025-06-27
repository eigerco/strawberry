package statetransition

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"sort"

	"github.com/eigerco/strawberry/internal/block"
	"github.com/eigerco/strawberry/internal/common"
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/crypto/bandersnatch"
	"github.com/eigerco/strawberry/internal/jamtime"
	"github.com/eigerco/strawberry/internal/safrole"
	"github.com/eigerco/strawberry/internal/state"
	"github.com/eigerco/strawberry/internal/validator"
)

// Input to UpdateSafroleState. Derived from the incoming block.
type SafroleInput struct {
	// Next timeslot.
	TimeSlot jamtime.Timeslot
	// Ticket extrinsic (E_T).
	Tickets []block.TicketProof
	// Y(Hv)
	Entropy crypto.BandersnatchOutputHash
}

func NewSafroleInputFromBlock(block block.Block) (SafroleInput, error) {
	entropy, err := bandersnatch.OutputHash(block.Header.VRFSignature)
	if err != nil {
		return SafroleInput{}, err
	}

	// TODO - might want to make a deep copy for ticket proofs and offenders
	// here, but should be ok since it's read only.
	return SafroleInput{
		TimeSlot: block.Header.TimeSlotIndex,
		Tickets:  block.Extrinsic.ET.TicketProofs,
		Entropy:  entropy,
	}, nil
}

// Output from UpdateSafroleState.
type SafroleOutput struct {
	// H_e
	EpochMark *block.EpochMarker
	// H_w
	WinningTicketMark *block.WinningTicketMarker

	// Entropies for use by downstream functions that might also use this output.
	TicketEntropy  crypto.Hash // n_2
	SealingEntropy crypto.Hash // n_3
}

// Validates then produces tickets from submitted ticket proofs.
// Implements equations 74-80 in the graypaper (v.0.4.5)
// ET ∈ D{r ∈ NN, p ∈ F̄[]γz⟨XT ⌢ η′2 r⟩}I  (74)
// |ET| ≤ K if m′ < Y                        (75)
// n ≡ [{y ▸ Y(ip), r ▸ ir} S i <− ET]      (76)
// n = [xy __ x ∈ n]                         (77)
// {xy S x ∈ n} ⫰ {xy S x ∈ γa}             (78)
// γ′a ≡ [xy^^ x ∈ n ∪ {∅ if e′ > e, γa otherwise}]E  (79)
func calculateTickets(safstate safrole.State, entropyPool state.EntropyPool, ticketProofs []block.TicketProof) ([]block.Ticket, error) {
	// Equation 75: |ET| ≤ K if m′ < Y (v.0.4.5)
	if len(ticketProofs) > common.MaxTicketExtrinsicSize {
		return []block.Ticket{}, errors.New("too many tickets")
	}

	ringVerifier, err := safstate.NextValidators.RingVerifier()
	defer ringVerifier.Free()
	if err != nil {
		return []block.Ticket{}, err
	}

	// Equation 78: {xy S x ∈ n} ⫰ {xy S x ∈ γa} (v.0.4.5)
	// Check for duplicate tickets in γ_a
	existingIds := make(map[crypto.BandersnatchOutputHash]struct{}, len(safstate.TicketAccumulator))
	for _, ticket := range safstate.TicketAccumulator {
		existingIds[ticket.Identifier] = struct{}{}
	}
	// Equations 74 and 76 (v.0.4.5)
	// ET ∈ D{r ∈ NN, p ∈ F̄[]γz⟨XT ⌢ η′2 r⟩}I
	// n ≡ [{y ▸ Y(ip), r ▸ ir} S i <− ET]
	tickets := make([]block.Ticket, len(ticketProofs))
	for i, tp := range ticketProofs {
		// Equation 6.29: r ∈ N_N (v.0.5.4)
		if tp.EntryIndex >= common.MaxTicketAttempts {
			return []block.Ticket{}, errors.New("bad ticket attempt")
		}

		// Validate the ring signature. VrfInputData is X_t ⌢ η_2′ ++ r. Equation 74. (v.0.4.5)
		vrfInputData := append([]byte(state.TicketSealContext), entropyPool[2][:]...)
		vrfInputData = append(vrfInputData, tp.EntryIndex)
		// This produces the output hash we need to construct the ticket further down.
		ok, outputHash := ringVerifier.Verify(vrfInputData, []byte{}, safstate.RingCommitment, tp.Proof)
		if !ok {
			return []block.Ticket{}, errors.New("bad ticket proof")
		}

		// Equation 78: {xy S x ∈ n} ⫰ {xy S x ∈ γa} (v.0.4.5)
		if _, exists := existingIds[outputHash]; exists {
			return []block.Ticket{}, errors.New("duplicate ticket")
		}

		// Equation 76: n ≡ [{y ▸ Y(ip), r ▸ ir} S i <− ET] (v.0.4.5)
		tickets[i] = block.Ticket{
			Identifier: outputHash,
			EntryIndex: tp.EntryIndex,
		}
	}

	// Equation 77: n = [xy __ x ∈ n] (v.0.4.5)
	// Verify tickets are ordered by identifier
	for i := 1; i < len(tickets); i++ {
		prevHash := tickets[i-1].Identifier
		currentHash := tickets[i].Identifier
		if bytes.Compare(prevHash[:], currentHash[:]) >= 0 {
			return []block.Ticket{}, errors.New("bad ticket order")
		}
	}

	return tickets, nil
}

// Implements section 6 of the graypaper.
// Updates all state associated with the SAFROLE protocol.
// Implements key equations (v.0.4.5)
// γ′k ≡ Φ(ι) if e′ > e                     (58)
// γ′s ≡ Z(γa) if e′ = e + 1 ∧ m ≥ Y ∧ |γa| = E
//
//	γs if e′ = e
//	F(η′2, κ′) otherwise                (69)
//
// He ≡ (η′1, [kb S k <− γ′k]) if e′ > e
//
//	∅ otherwise                          (72)
//
// Hw ≡ Z(γa) if e′ = e ∧ m < Y ≤ m′ ∧ |γa| = E
//
//	∅ otherwise                          (73)
func UpdateSafroleState(
	input SafroleInput,
	preTimeSlot jamtime.Timeslot,
	entropyPool state.EntropyPool,
	validatorState validator.ValidatorState,
	offenders []ed25519.PublicKey,
) (state.EntropyPool, validator.ValidatorState, SafroleOutput, error) {
	if input.TimeSlot <= preTimeSlot {
		return entropyPool, validatorState, SafroleOutput{}, errors.New("bad slot")
	}

	nextTimeSlot := input.TimeSlot

	// Equations 67, 68 (v.0.4.5)
	// η′0 ≡ H(η0 ⌢ Y(Hv))
	// (η′1, η′2, η′3) ≡ (η0, η1, η2) if e′ > e
	newEntropyPool, err := calculateNewEntropyPool(preTimeSlot, nextTimeSlot, input.Entropy, entropyPool)
	if err != nil {
		return entropyPool, validatorState, SafroleOutput{}, err
	}

	newValidatorState := validatorState
	output := SafroleOutput{
		TicketEntropy:  newEntropyPool[2],
		SealingEntropy: newEntropyPool[3],
	}

	epoch := nextTimeSlot.ToEpoch()   // e'
	preEpoch := preTimeSlot.ToEpoch() // e
	// |γ_a| = E, a condition of equation 73.
	ticketAccumulatorFull := len(validatorState.SafroleState.TicketAccumulator) == jamtime.TimeslotsPerEpoch

	// Note that this condition allows epochs to be skipped, e' > e, as in equations 58, 68, 72. (v.0.4.5)
	// We don't care about the timeslot, only the epoch.
	// Equation 58: (γ′k, κ′, λ′, γ′z) ≡ (Φ(ι), γk, κ, z) if e′ > e
	if epoch > preEpoch {
		// Equation 59: Φ(k) ≡ [0, 0, ...] if ke ∈ ψ′o (v.0.4.5)
		//                     k otherwise
		newValidatorState.SafroleState.NextValidators = validator.NullifyOffenders(validatorState.QueuedValidators, offenders)
		newValidatorState.CurrentValidators = validatorState.SafroleState.NextValidators
		newValidatorState.ArchivedValidators = validatorState.CurrentValidators

		// Calculate new ring commitment. (γ_z) . Apply the O function from equation 58.
		//  Equation 58: z = O([kb S k <− γ′k])
		ringCommitment, err := newValidatorState.SafroleState.NextValidators.RingCommitment()
		if err != nil {
			return entropyPool, validatorState, SafroleOutput{}, errors.New("unable to calculate ring commitment")
		}
		newValidatorState.SafroleState.RingCommitment = ringCommitment

		// Determine the sealing keys.  Standard way is to use
		// tickets as sealing keys, if we can't then fall back to selecting
		// bandersnatch validator keys for sealing randomly using past entropy.
		// Equation 69: γ′s ≡ Z(γa) if e′ = e + 1 ∧ m ≥ Y ∧ |γa| = E (v.0.4.5)
		//                    γs if e′ = e
		//                    F(η′2, κ′) otherwise
		if epoch == preEpoch+jamtime.Epoch(1) &&
			// m >= Y
			!preTimeSlot.IsTicketSubmissionPeriod() &&
			// |γ_a| = E
			ticketAccumulatorFull {
			// Use tickets for sealing keys. Apply the Z function on the ticket accumulator.
			sealingTickets := safrole.OutsideInSequence(newValidatorState.SafroleState.TicketAccumulator)
			newValidatorState.SafroleState.SealingKeySeries.Set(safrole.TicketsBodies(sealingTickets))
		} else {
			// Use bandersnatch keys for sealing keys.
			fallbackKeys, err := safrole.SelectFallbackKeys(newEntropyPool[2], newValidatorState.CurrentValidators)
			if err != nil {
				return entropyPool, validatorState, SafroleOutput{}, err
			}
			newValidatorState.SafroleState.SealingKeySeries.Set(fallbackKeys)
		}

		// Compute epoch marker (H_e).
		// Equation 6.27: He ≡ (η0, n1, [kb S k <− γ′k]) if e′ > e (v.0.5.4)
		output.EpochMark = &block.EpochMarker{
			Entropy:        entropyPool[0],
			TicketsEntropy: entropyPool[1],
		}
		for i, vd := range newValidatorState.SafroleState.NextValidators {
			output.EpochMark.Keys[i] = block.ValidatorKeys{
				Bandersnatch: vd.Bandersnatch,
				Ed25519:      vd.Ed25519,
			}
		}

		// Reset ticket accumulator. From equation 79.
		newValidatorState.SafroleState.TicketAccumulator = []block.Ticket{}
	}

	// Check if we need to generate the winning tickets marker.
	// // Equation 73: Hw ≡ Z(γa) if e′ = e ∧ m < Y ≤ m′ ∧ |γa| = E (v.0.4.5)
	if epoch == preEpoch &&
		nextTimeSlot.IsWinningTicketMarkerPeriod(preTimeSlot) &&
		ticketAccumulatorFull {
		// Apply the Z function to the ticket accumulator.
		winningTickets := safrole.OutsideInSequence(newValidatorState.SafroleState.TicketAccumulator)
		output.WinningTicketMark = (*block.WinningTicketMarker)(winningTickets)
	}

	// Process incoming tickets.  Check if we're still allowed to submit
	// tickets. An implication of equation 75. m' < Y to submit.
	if !nextTimeSlot.IsTicketSubmissionPeriod() && len(input.Tickets) > 0 {
		return entropyPool, validatorState, SafroleOutput{}, errors.New("unexpected ticket")
	}

	if len(input.Tickets) > 0 {
		// Validate ticket proofs and produce tickets. Tickets produced are n.
		// As in equation 76.
		tickets, err := calculateTickets(newValidatorState.SafroleState, newEntropyPool, input.Tickets)
		if err != nil {
			return entropyPool, validatorState, SafroleOutput{}, err
		}

		// Update the accumulator γ_a.
		// Equation 79: γ′a ≡ [xy^^ x ∈ n ∪ {∅ if e′ > e, γa otherwise}]E (v.0.4.5)
		// Combine existing and new tickets.
		accumulator := newValidatorState.SafroleState.TicketAccumulator
		allTickets := make([]block.Ticket, len(accumulator)+len(tickets))
		copy(allTickets, accumulator)
		copy(allTickets[len(accumulator):], tickets)

		// Resort by identifier.
		sort.Slice(allTickets, func(i, j int) bool {
			return bytes.Compare(allTickets[i].Identifier[:], allTickets[j].Identifier[:]) < 0
		})

		// Drop older tickets, limiting the accumulator to |E|.
		if len(allTickets) > jamtime.TimeslotsPerEpoch {
			allTickets = allTickets[:jamtime.TimeslotsPerEpoch]
		}

		// Ensure all incoming tickets exist in the accumulator. No useless
		// tickets are allowed. Equation 6.35: n ⊆ γ′a (v.0.5.4)
		existingIds := make(map[crypto.BandersnatchOutputHash]struct{}, len(allTickets))
		for _, ticket := range allTickets {
			existingIds[ticket.Identifier] = struct{}{}
		}
		for _, ticket := range tickets {
			if _, ok := existingIds[ticket.Identifier]; !ok {
				return entropyPool, validatorState, SafroleOutput{}, errors.New("useless ticket")
			}
		}
		newValidatorState.SafroleState.TicketAccumulator = allTickets
	}

	return newEntropyPool, newValidatorState, output, nil
}

// Implements equations 67 and 68 from the graypaper. (v.0.4.5)
// The entropyInput is assumed to be bandersnatch output hash from the block vrf siganture, Y(Hv).
// The entryPool is defined as equation 66.
// Calculates η′0 ≡ H(η0 ⌢ Y(Hv)) every slot, and rotates the entropies on epoch change.
func calculateNewEntropyPool(currentTimeslot jamtime.Timeslot, newTimeslot jamtime.Timeslot, entropyInput crypto.BandersnatchOutputHash, entropyPool state.EntropyPool) (state.EntropyPool, error) {
	newEntropyPool := entropyPool

	if newTimeslot.ToEpoch() > currentTimeslot.ToEpoch() {
		newEntropyPool = rotateEntropyPool(entropyPool)
	}

	newEntropyPool[0] = crypto.HashData(append(entropyPool[0][:], entropyInput[:]...))
	return newEntropyPool, nil
}

func rotateEntropyPool(pool state.EntropyPool) state.EntropyPool {
	pool[3] = pool[2]
	pool[2] = pool[1]
	pool[1] = pool[0]
	return pool
}

// Determines the next SAFROLE state. Useful for functions that need to
// determine the SAFROLE state outside of the main UpdateState function. It
// makes dealing with all the edge cases on epoch change much easier. Returns
// the next ValidatorState together with the SAFROLE output which includes the
// entropy entries to use for ticket submission and block sealing. Disputes only
// need to be included in specific cases where an updated pending validator set
// (γ_k) is required for some calculation.
func NextSafroleState(priorState *state.State, nextTimeslot jamtime.Timeslot, disputes block.DisputeExtrinsic) (
	validator.ValidatorState,
	SafroleOutput,
	error) {
	newJudgements, err := CalculateNewJudgements(priorState.TimeslotIndex, disputes, priorState.PastJudgements, priorState.ValidatorState)
	if err != nil {
		return validator.ValidatorState{}, SafroleOutput{}, err
	}
	input := SafroleInput{
		TimeSlot: nextTimeslot,
		// Empty because at this point we don't yet have Y(Hv) nor do we ever
		// need it for anything that might use this function. We only ever care
		// about the entropy pool's 1st to 3rd indexes.
		Entropy: crypto.BandersnatchOutputHash{},
	}

	_, validatorState, output, err := UpdateSafroleState(input, priorState.TimeslotIndex, priorState.EntropyPool, priorState.ValidatorState, newJudgements.OffendingValidators)
	if err != nil {
		return validator.ValidatorState{}, SafroleOutput{}, err
	}

	return validatorState, output, nil
}
