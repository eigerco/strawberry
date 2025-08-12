package state

import (
	"bytes"
	"crypto/ed25519"
	"sort"

	"github.com/eigerco/strawberry/internal/block"
	"github.com/eigerco/strawberry/internal/common"
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/jamtime"
	"github.com/eigerco/strawberry/internal/safrole"
	"github.com/eigerco/strawberry/internal/service"
	"github.com/eigerco/strawberry/pkg/serialization/codec/jam"
)

type Assignment struct {
	WorkReport block.WorkReport // Work-Report (r)
	Time       jamtime.Timeslot // time at which work-report was reported but not yet accumulated (t)
}

type Judgements struct {
	GoodWorkReports     []crypto.Hash       // Good work-reports (ψG) - Work-reports judged to be correct.
	BadWorkReports      []crypto.Hash       // Bad work-reports (ψB) - Work-reports judged to be incorrect.
	WonkyWorkReports    []crypto.Hash       // Wonky work-reports (ψW) - Work-reports whose validity is judged to be unknowable.
	OffendingValidators []ed25519.PublicKey // Offending validators (ψO) - Validators who made a judgement found to be incorrect.
}

// Note that unmarshaling is not implemented given that we sort when serializing.
func (j Judgements) MarshalJAM() ([]byte, error) {
	encodedCopy := struct {
		GoodWorkReports     []crypto.Hash
		BadWorkReports      []crypto.Hash
		WonkyWorkReports    []crypto.Hash
		OffendingValidators []ed25519.PublicKey
	}{
		GoodWorkReports:     make([]crypto.Hash, len(j.GoodWorkReports)),
		BadWorkReports:      make([]crypto.Hash, len(j.BadWorkReports)),
		WonkyWorkReports:    make([]crypto.Hash, len(j.WonkyWorkReports)),
		OffendingValidators: make([]ed25519.PublicKey, len(j.OffendingValidators)),
	}

	// Copy and sort each of the slices.
	copy(encodedCopy.GoodWorkReports, j.GoodWorkReports)
	sort.Slice(encodedCopy.GoodWorkReports, func(i, j int) bool {
		return bytes.Compare(encodedCopy.GoodWorkReports[i][:], encodedCopy.GoodWorkReports[j][:]) < 0
	})

	copy(encodedCopy.BadWorkReports, j.BadWorkReports)
	sort.Slice(encodedCopy.BadWorkReports, func(i, j int) bool {
		return bytes.Compare(encodedCopy.BadWorkReports[i][:], encodedCopy.BadWorkReports[j][:]) < 0
	})

	copy(encodedCopy.WonkyWorkReports, j.WonkyWorkReports)
	sort.Slice(encodedCopy.WonkyWorkReports, func(i, j int) bool {
		return bytes.Compare(encodedCopy.WonkyWorkReports[i][:], encodedCopy.WonkyWorkReports[j][:]) < 0
	})

	copy(encodedCopy.OffendingValidators, j.OffendingValidators)
	sort.Slice(encodedCopy.OffendingValidators, func(i, j int) bool {
		return bytes.Compare(encodedCopy.OffendingValidators[i], encodedCopy.OffendingValidators[j]) < 0
	})

	return jam.Marshal(encodedCopy)
}

type CoreAssignments [common.TotalNumberOfCores]*Assignment

type PendingAuthorizersQueue [PendingAuthorizersQueueSize]crypto.Hash
type PendingAuthorizersQueues [common.TotalNumberOfCores]PendingAuthorizersQueue

type EntropyPool [EntropyPoolSize]crypto.Hash
type CoreAuthorizersPool [common.TotalNumberOfCores][]crypto.Hash // TODO: Maximum length per core: MaxAuthorizersPerCore

type WorkReportWithUnAccumulatedDependencies struct {
	WorkReport   block.WorkReport
	Dependencies map[crypto.Hash]struct{} // Set of Dependencies (Work-Package Hashes related to work report)
}

// AccumulationQueue ω ∈ ⟦⟦(R, {H})⟧⟧_E (eq. 12.3 v0.7.0)
type AccumulationQueue [jamtime.TimeslotsPerEpoch][]WorkReportWithUnAccumulatedDependencies

// AccumulationHistory ξ ∈ ⟦{H}⟧_E (eq. 12.1 v0.7.0)
type AccumulationHistory [jamtime.TimeslotsPerEpoch]map[crypto.Hash]struct{}

// AccumulationState characterization of state components (eq. 12.13 v0.7.0)
type AccumulationState struct {
	ServiceState             service.ServiceState                               // Service accounts δ (d ∈ D⟨NS → A⟩)
	ValidatorKeys            safrole.ValidatorsData                             // Validator keys ι (i ∈ ⟦K⟧V)
	PendingAuthorizersQueues [common.TotalNumberOfCores]PendingAuthorizersQueue // Queue of authorizers ϕ (q ∈ C⟦H⟧QHC)
	ManagerServiceId         block.ServiceId                                    // (m)
	AssignedServiceIds       [common.TotalNumberOfCores]block.ServiceId         // (a)
	DesignateServiceId       block.ServiceId                                    // (u)
	AmountOfGasPerServiceId  map[block.ServiceId]uint64                         // (z)
}

// AccumulationOperand represents a single operand for accumulation (I) (eq. 12.19 v0.6.7)
type AccumulationOperand struct {
	WorkPackageHash   crypto.Hash // Work-package hash (p ∈ H)
	SegmentRoot       crypto.Hash // Segment root (e ∈ H)
	AuthorizationHash crypto.Hash // Authorization hash (a ∈ H)
	PayloadHash       crypto.Hash // Payload hash (y ∈ H)
	GasLimit          uint64      `jam:"encoding=compact"` // Gas limit (g ∈ NG)
	// TODO revert back the order of fields when upgrading to v0.7.x
	OutputOrError block.WorkResultOutputOrError // Output or error (l ∈ B ∪ E)
	Trace         []byte                        // Trace of the work report (t ∈ B)
}

// AccumulationOutputLog θ ∈ ⟦(NS, H)⟧ (eq. 7.4)
type AccumulationOutputLog []ServiceHashPair

type ServiceHashPair struct {
	ServiceId block.ServiceId
	Hash      crypto.Hash
}
