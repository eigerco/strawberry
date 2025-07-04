package assuring

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"slices"

	"github.com/eigerco/strawberry/internal/block"
	"github.com/eigerco/strawberry/internal/common"
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/jamtime"
	"github.com/eigerco/strawberry/internal/safrole"
	"github.com/eigerco/strawberry/internal/state"
	"github.com/eigerco/strawberry/pkg/serialization/codec/jam"
)

// CalculateIntermediateCoreAssignmentsAndAvailableWorkReports implements equations
//
//	4.13: ρ‡ ≺ (EA, ρ†)
//	4.15: R* ≺ (EA, ρ†)
//
// It calculates the intermediate core assignments based on availability
// assurances, and also returns the set of now avaiable work reports.
// Reports that are made available are returned (to be used in Accumulation). Reports that are timedout are discarded.
// The reports that are left are returned as new core assignments (kept in the cores).
// (GP v0.7.0)
func CalculateIntermediateCoreAssignmentsAndAvailableWorkReports(ae block.AssurancesExtrinsic, validators safrole.ValidatorsData,
	IntermediateCoreAssignments state.CoreAssignments, header block.Header) (state.CoreAssignments, []block.WorkReport, error) {
	if err := validateAssurancesExtrinsic(ae, validators, IntermediateCoreAssignments, header); err != nil {
		return IntermediateCoreAssignments, nil, err
	}

	// Initialize availability count for each core
	availabilityCounts := make(map[uint16]int)

	// Process each assurance in the AssurancesExtrinsic (EA)
	// Check the availability status for each core in this assurance
	for coreIndex := range common.TotalNumberOfCores {
		for _, assurance := range ae {
			// Check if the bit corresponding to this core is set (1) in the Bitfield
			// af[c] ⇒ ρ†[c] ≠ ∅ (eq. 11.15)
			if assurance.IsForCore(coreIndex) {
				if IntermediateCoreAssignments[coreIndex] == nil {
					return IntermediateCoreAssignments, nil, errors.New("core not engaged")
				}
				// If set, increment the availability count for this core
				availabilityCounts[coreIndex]++
			}
		}
	}

	// R, the set of work reports that have become available.
	// R ≡ [ρ†[c]r | c ← NC, Σa∈EA af[c] > 2/3|V|](eq. 11.16)
	var availableReports []block.WorkReport
	// Update assignments based on availability
	// ∀c ∈ NC : ρ‡[c] ≡ { ∅ if ρ[c]r ∈ R ∨ HT ≥ ρ†[c]t + U
	//                    ρ†[c] otherwise }
	for coreIndex := range common.TotalNumberOfCores {
		availCountForCore, ok := availabilityCounts[coreIndex]
		// Remove core if:
		// 1. There are availability assurances for this core, and they exceed the threshold, i.e > 2/3 of validators are assuring
		// 2. Assignment report is stale, the report is older than U timeslots ago and should timeout.
		if ok && availCountForCore > common.AvailabilityThreshold {
			// Add any report that is made available to the W set. Note this
			// includes reports that could already be timed out. We are lenient
			// here, as long as they are made available they get added to the
			// set.
			availableReports = append(availableReports, IntermediateCoreAssignments[coreIndex].WorkReport)
			IntermediateCoreAssignments[coreIndex] = nil
		}
		// Any report that isn't lucky enough to be made available is timed out and removed.
		if isAssignmentStale(IntermediateCoreAssignments[coreIndex], header.TimeSlotIndex) {
			IntermediateCoreAssignments[coreIndex] = nil
		}
	}

	// Return the new intermediate CoreAssignments (ρ‡), along with the newly available reports. (R)
	return IntermediateCoreAssignments, availableReports, nil
}

func validateAssurancesExtrinsic(ae block.AssurancesExtrinsic, validators safrole.ValidatorsData, coreAssignments state.CoreAssignments, header block.Header) error {
	for _, a := range ae {
		// ∀a ∈ EA : aa = Hp (eq. 11.11 v0.7.0)
		if a.Anchor != header.ParentHash {
			return errors.New("bad attestation parent")
		}
		if int(a.ValidatorIndex) >= common.NumberOfValidators || validators[a.ValidatorIndex].IsEmpty() {
			return errors.New("bad validator index")
		}
	}
	// ∀i ∈ {1 ... |E_A|} ∶ EA[i − 1]v < EA[i]v (11.12 v0.7.0)
	if !assuranceIsSortedUnique(ae) {
		return errors.New("not sorted or unique assurers")
	}

	// ∀a ∈ EA : as ∈ V̄κ[av]e⟨XA ⌢ H(E(HP, af))⟩ (eq. 11.13 v 0.7.0)
	if err := verifySignatures(ae, validators, header); err != nil {
		return err
	}

	// ∀a ∈ EA, c ∈ NC : af[c] ⇒ ρ†[c] ≠ ∅ (eq. 11.15 v 0.7.0)
	for coreIndex := range common.TotalNumberOfCores {
		for _, a := range ae {
			if a.IsForCore(coreIndex) {
				if coreAssignments[coreIndex] == nil {
					return errors.New("core not engaged")
				}
			}
		}
	}

	return nil
}

// HT ≥ ρ†[c]t + U (Part of equation eq. 11.17 v 0.7.0)
func isAssignmentStale(currentAssignment *state.Assignment, newTimeslot jamtime.Timeslot) bool {
	return currentAssignment != nil && newTimeslot >= currentAssignment.Time+common.WorkReportTimeoutPeriod
}

// ∀i ∈ {1...|EA|} : EA[i-1]v < EA[i]v (eq. 11.12 v 0.7.0)
func assuranceIsSortedUnique(assurances block.AssurancesExtrinsic) bool {
	return slices.IsSortedFunc(assurances, func(a, b block.Assurance) int {
		if a.ValidatorIndex > b.ValidatorIndex {
			return 1
		}
		return -1
	})
}

// ∀a ∈ EA : as ∈ V̄κ[av]e⟨XA ⌢ H(E(HP, af))⟩ (eq. 11.13 v 0.7.0)
func verifySignatures(ae block.AssurancesExtrinsic, validators safrole.ValidatorsData, header block.Header) error {
	for _, a := range ae {
		var message []byte
		b, err := jam.Marshal(header.ParentHash)
		if err != nil {
			return fmt.Errorf("error encoding header parent hash %w", err)
		}
		message = append(message, b...)
		b, err = jam.Marshal(a.Bitfield)
		if err != nil {
			return fmt.Errorf("error encoding assurance bitfield %w", err)
		}
		message = append(message, b...)
		messageHash := crypto.HashData(message)
		if !ed25519.Verify(validators[a.ValidatorIndex].Ed25519, append([]byte(state.SignatureContextAvailable), messageHash[:]...), a.Signature[:]) {
			return errors.New("bad signature")
		}
	}
	return nil
}
