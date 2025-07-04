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
	"github.com/eigerco/strawberry/internal/disputing"
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
	// Y(H_V)
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
	// H_E
	EpochMark *block.EpochMarker
	// H_W
	WinningTicketMark *block.WinningTicketMarker

	// Entropies for use by downstream functions that might also use this output.
	TicketEntropy  crypto.Hash // n_2
	SealingEntropy crypto.Hash // n_3
}

// Validates then produces tickets from submitted ticket proofs.
// Implements equations 6.29-6.34
// E_T ∈ D{e ∈ N_N, p ∈ V[]γ'z⟨X_T ⌢ η′2 ++ e⟩}  (6.29)
// |E_T| ≤ K if m′ < Y                           (6.30)
// n ≡ [(y: Y(i_p), e: i_e) | i <− E_T]          (6.31)
// n = [x ∈ n || x_y]                            (6.32)
// {x_y | x ∈ n} ⫰ {x_y | x ∈ γ_A}               (6.33)
// γ′A ≡ [x ∈ n ∪ {∅ if e′ > e, γ_A otherwise}]E (6.34)
// GP v0.7.0
func calculateTickets(safstate safrole.State, entropyPool state.EntropyPool, ticketProofs []block.TicketProof) ([]block.Ticket, error) {
	// Equation 6.30: |E_T| ≤ K if m′ < Y
	if len(ticketProofs) > common.MaxTicketExtrinsicSize {
		return []block.Ticket{}, errors.New("too many tickets")
	}

	ringVerifier, err := safstate.NextValidators.RingVerifier()
	defer ringVerifier.Free()
	if err != nil {
		return []block.Ticket{}, err
	}

	// Equation 6.33: {x_y | x ∈ n} ⫰ {x_y | x ∈ γ_A}
	// Check for duplicate tickets in γ_a
	existingIds := make(map[crypto.BandersnatchOutputHash]struct{}, len(safstate.TicketAccumulator))
	for _, ticket := range safstate.TicketAccumulator {
		existingIds[ticket.Identifier] = struct{}{}
	}
	// Equations 6.29 and 6.31
	// E_T ∈ D{e ∈ N_N, p ∈ V[]γ'z⟨X_T ⌢ η′2 ++ e⟩}
	// n ≡ [(y: Y(i_p), e: i_e) | i <− E_T]
	tickets := make([]block.Ticket, len(ticketProofs))
	for i, tp := range ticketProofs {
		// Equation 6.29: e ∈ N_N
		if tp.EntryIndex >= common.MaxTicketAttemptsPerValidator {
			return []block.Ticket{}, errors.New("bad ticket attempt")
		}

		// Validate the ring signature. VrfInputData is X_t ⌢ η_2′ ++ r. Equation 6.29
		vrfInputData := append([]byte(state.TicketSealContext), entropyPool[2][:]...)
		vrfInputData = append(vrfInputData, tp.EntryIndex)
		// This produces the output hash we need to construct the ticket further down.
		ok, outputHash := ringVerifier.Verify(vrfInputData, []byte{}, safstate.RingCommitment, tp.Proof)
		if !ok {
			return []block.Ticket{}, errors.New("bad ticket proof")
		}

		// Equation 6.33: {x_y | x ∈ n} ⫰ {x_y | x ∈ γ_A}
		if _, exists := existingIds[outputHash]; exists {
			return []block.Ticket{}, errors.New("duplicate ticket")
		}

		// Equation 6.31: n ≡ [(y: Y(i_p), e: i_e) | i <− E_T]
		tickets[i] = block.Ticket{
			Identifier: outputHash,
			EntryIndex: tp.EntryIndex,
		}
	}

	// Equation 6.32: n = [x ∈ n || x_y]
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
// Implements key equations:
// γ′_P ≡ Φ(ι) if e′ > e                     (6.13)
// T ≡ Z(γ_A) if e′ = e + 1 ∧ m ≥ Y ∧ |γ_A| = E
//
//	γ_s if e′ = e
//	F(η′2, κ′) otherwise                     (6.24)
//
// H_E ≡ (n0, η1, [(k_b, k_e) | k <− γ′_P]) if e′ > e
//
//	∅ otherwise                              (6.27)
//
// H_W ≡ Z(γ_A) if e′ = e ∧ m < Y ≤ m′ ∧ |γ_A| = E
//
//	∅ otherwise                              (6.28)
//
// GP v0.7.0
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

	// Equations 6.22, 6.23
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
	// |γ_A| = E, a condition of equation 6.24
	ticketAccumulatorFull := len(validatorState.SafroleState.TicketAccumulator) == jamtime.TimeslotsPerEpoch

	// Note that this condition allows epochs to be skipped, e' > e, as in equations 6.13, 6.23, 6.27
	// We don't care about the timeslot, only the epoch.
	// Equation 6.13 (γ′P, κ′, λ′, γ′z) ≡ (Φ(ι), γ_P, κ, z) if e′ > e
	if epoch > preEpoch {
		// Equation 6.14: Φ(k) ≡ [0, 0, ...] if ke ∈ ψ′o
		//                     k otherwise
		newValidatorState.SafroleState.NextValidators = validator.NullifyOffenders(validatorState.QueuedValidators, offenders)
		newValidatorState.CurrentValidators = validatorState.SafroleState.NextValidators
		newValidatorState.ArchivedValidators = validatorState.CurrentValidators

		// Calculate new ring commitment. (γ_z) . Apply the O function from equation 58.
		//  Equation 6.13: z = O([k_b | k <− γ′P])
		ringCommitment, err := newValidatorState.SafroleState.NextValidators.RingCommitment()
		if err != nil {
			return entropyPool, validatorState, SafroleOutput{}, errors.New("unable to calculate ring commitment")
		}
		newValidatorState.SafroleState.RingCommitment = ringCommitment

		// Determine the sealing keys.  Standard way is to use
		// tickets as sealing keys, if we can't then fall back to selecting
		// bandersnatch validator keys for sealing randomly using past entropy.
		// Equation 6.24: T ≡ Z(γ_A) if e′ = e + 1 ∧ m ≥ Y ∧ |γ_A| = E
		//                    γ_s if e′ = e
		//                    F(η′2, κ′) otherwise
		if epoch == preEpoch+jamtime.Epoch(1) &&
			// m >= Y
			!preTimeSlot.IsTicketSubmissionPeriod() &&
			// |γ_A| = E
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

		// Compute epoch marker (H_E).
		// Equation 6.27: He ≡ (η0, n1, [(k_b, k_e) | k <− γ′P]) if e′ > e
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

		// Reset ticket accumulator. From equation 6.34
		// y'_A = ∅ if e′ > e
		newValidatorState.SafroleState.TicketAccumulator = []block.Ticket{}
	}

	// Check if we need to generate the winning tickets marker.
	// // Equation 6.28: H_W ≡ Z(γ_A) if e′ = e ∧ m < Y ≤ m′ ∧ |γ_A| = E
	if epoch == preEpoch &&
		nextTimeSlot.IsWinningTicketMarkerPeriod(preTimeSlot) &&
		ticketAccumulatorFull {
		// Apply the Z function to the ticket accumulator.
		winningTickets := safrole.OutsideInSequence(newValidatorState.SafroleState.TicketAccumulator)
		output.WinningTicketMark = (*block.WinningTicketMarker)(winningTickets)
	}

	// Process incoming tickets. Check if we're still allowed to submit
	// tickets. An implication of equation 6.30: m' < Y to submit.
	if !nextTimeSlot.IsTicketSubmissionPeriod() && len(input.Tickets) > 0 {
		return entropyPool, validatorState, SafroleOutput{}, errors.New("unexpected ticket")
	}

	if len(input.Tickets) > 0 {
		// Validate ticket proofs and produce tickets. Tickets produced are n.
		// As in equation 6.31-6.33
		tickets, err := calculateTickets(newValidatorState.SafroleState, newEntropyPool, input.Tickets)
		if err != nil {
			return entropyPool, validatorState, SafroleOutput{}, err
		}

		// Update the accumulator γ_A.
		// Equation 6.34: γ′A ≡ [x ∈ n ∪ {∅ if e′ > e, γ_A otherwise}]E
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
		// tickets are allowed. Equation 6.35: n ⊆ γ′A
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

// Calculates η′0 ≡ H(η0 ⌢ Y(Hv)) every slot (6.22)
// and rotates the entropies on epoch change:
// (η1′​,η2′​,η3′​) = {(η0​,η1​,η2​) ​if e′>e (η1​,η2​,η3​) otherwise​ (6.23)
// The entropyInput is assumed to be bandersnatch output hash from the block vrf siganture, Y(Hv).
// The entryPool is defined as equation 6.21: η ∈ ⟦H⟧_4
// GP v0.7.0
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
// (γ_P) is required for some calculation.
func NextSafroleState(priorState *state.State, nextTimeslot jamtime.Timeslot, de block.DisputeExtrinsic) (
	validator.ValidatorState,
	SafroleOutput,
	error) {
	newJudgements, err := disputing.ValidateDisputesExtrinsicAndProduceJudgements(priorState.TimeslotIndex, de, priorState.ValidatorState, priorState.PastJudgements)
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
