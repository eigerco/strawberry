package state

import (
	"bytes"
	"crypto/ed25519"
	"io"
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
	WorkReport *block.WorkReport // Work-Report (w)
	Time       jamtime.Timeslot  // time at which work-report was reported but not yet accumulated (t)
}

// TODO remove this when we refactor Assigment's WorkReport to not be a pointer.
func (a *Assignment) MarshalJAM() ([]byte, error) {
	if a == nil {
		// Return the nil pointer marker.
		return []byte{0x00}, nil
	}

	assignment := struct {
		WorkReport block.WorkReport
		Time       jamtime.Timeslot
	}{
		WorkReport: *a.WorkReport,
		Time:       a.Time,
	}

	// Make sure to write a pointer back.
	return jam.Marshal(&assignment)
}

// TODO remove this when we refactor Assigment's WorkReport to not be a pointer.
func (a *Assignment) UnmarshalJAM(reader io.Reader) error {
	var assignment struct {
		WorkReport block.WorkReport
		Time       jamtime.Timeslot
	}
	decoder := jam.NewDecoder(reader)
	if err := decoder.Decode(&assignment); err != nil {
		return err
	}
	a.WorkReport = &assignment.WorkReport
	a.Time = assignment.Time

	return nil
}

type Judgements struct {
	GoodWorkReports     []crypto.Hash       //  Good work-reports (ψg) - Work-reports judged to be correct.
	BadWorkReports      []crypto.Hash       //  Bad work-reports (ψb) - Work-reports judged to be incorrect.
	WonkyWorkReports    []crypto.Hash       //  Wonky work-reports (ψw) - Work-reports whose validity is judged to be unknowable.
	OffendingValidators []ed25519.PublicKey //  Offending validators (ψp) - CurrentValidators who made a judgement found to be incorrect.
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

type AccumulationQueue [jamtime.TimeslotsPerEpoch][]WorkReportWithUnAccumulatedDependencies

type AccumulationHistory [jamtime.TimeslotsPerEpoch]map[crypto.Hash]struct{} // (equation 162 v0.4.5)

// AccumulationState characterization of state components (equation 174 v0.4.5)
type AccumulationState struct {
	ServiceState             service.ServiceState                               // Service accounts δ (d ∈ D⟨NS → A⟩)
	ValidatorKeys            safrole.ValidatorsData                             // Validator keys ι (i ∈ ⟦K⟧V)
	PendingAuthorizersQueues [common.TotalNumberOfCores]PendingAuthorizersQueue // Queue of authorizers (q ∈ C⟦H⟧QHC)
	PrivilegedServices       service.PrivilegedServices                         // Privileges state (x ∈ (NS, NS, NS, D⟨NS → NG⟩))
}

// AccumulationOperand represents a single operand for accumulation (eq. 12.19)
type AccumulationOperand struct {
	WorkPackageHash   crypto.Hash                   // Work-package hash (h ∈ H)
	SegmentRoot       crypto.Hash                   // Segment root (e ∈ H)
	AuthorizationHash crypto.Hash                   // Authorization hash (a ∈ H)
	Output            []byte                        // Output of the work report (o ∈ Y)
	PayloadHash       crypto.Hash                   // Payload hash (y ∈ H)
	GasLimit          uint64                        `jam:"encoding=compact"` // Gas limit (g ∈ NG)
	OutputOrError     block.WorkResultOutputOrError // Output or error (d ∈ Y ∪ J)
}

// AccumulationResult represents the result type from equation 162:
// A: NS → {s ∈ A?, v ∈ ⟦K⟧V, t ∈ ⟦T⟧, r ∈ H?, c ∈ C⟦H⟧QHC, n ∈ D⟨NS → A⟩, p ∈ {m,a,v ∈ NS, g ∈ D⟨NS → NG⟩}}
type AccumulationResult struct {
	ServiceState      *service.ServiceAccount    // s - Optional updated service account state
	ValidatorUpdates  safrole.ValidatorsData     // v - Single validator data set, not a slice
	DeferredTransfers []service.DeferredTransfer // t - Deferred transfers sequence
	AccumulationRoot  *crypto.Hash               // r - Optional accumulation result hash
	CoreAssignments   PendingAuthorizersQueues   // c - Core authorizations queue
	NewServices       service.ServiceState       // n - Newly created services mapping
	PrivilegedUpdates struct {                   // p - Privileged service updates
		ManagerServiceId   block.ServiceId            // m - Manager service
		AssignServiceId    block.ServiceId            // a - Assign service
		DesignateServiceId block.ServiceId            // v - Designate service
		GasAssignments     map[block.ServiceId]uint64 // g - Gas assignments
	}
}

// AccumulationOutputLog θ ∈ ⟦(NS, H)⟧ (eq. 7.4)
type AccumulationOutputLog []ServiceHashPair

type ServiceHashPair struct {
	ServiceId block.ServiceId
	Hash      crypto.Hash
}
