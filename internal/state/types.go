package state

import (
	"crypto/ed25519"

	"github.com/eigerco/strawberry/internal/block"
	"github.com/eigerco/strawberry/internal/common"
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/jamtime"
	"github.com/eigerco/strawberry/internal/safrole"
	"github.com/eigerco/strawberry/internal/service"
)

type Assignment struct {
	WorkReport *block.WorkReport // Work-Report (w)
	Time       jamtime.Timeslot  // time at which work-report was reported but not yet accumulated (t)
}

type Judgements struct {
	BadWorkReports      []crypto.Hash       //  Bad work-reports (ψb) - Work-reports judged to be incorrect.
	GoodWorkReports     []crypto.Hash       //  Good work-reports (ψg) - Work-reports judged to be correct.
	WonkyWorkReports    []crypto.Hash       //  Wonky work-reports (ψw) - Work-reports whose validity is judged to be unknowable.
	OffendingValidators []ed25519.PublicKey //  Offending validators (ψp) - CurrentValidators who made a judgement found to be incorrect.
}

type CoreAssignments [common.TotalNumberOfCores]*Assignment

type PendingAuthorizersQueues [common.TotalNumberOfCores][PendingAuthorizersQueueSize]crypto.Hash

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
	ServiceState             service.ServiceState                                                // Service accounts δ (d ∈ D⟨NS → A⟩)
	ValidatorKeys            safrole.ValidatorsData                                              // Validator keys ι (i ∈ ⟦K⟧V)
	PendingAuthorizersQueues [common.TotalNumberOfCores][PendingAuthorizersQueueSize]crypto.Hash // Queue of authorizers (q ∈ C⟦H⟧QHC)
	PrivilegedServices       service.PrivilegedServices                                          // Privileges state (x ∈ (NS, NS, NS, D⟨NS → NG⟩))
}

// AccumulationOperand represents a single operand for accumulation (equation 179 v0.4.5)
type AccumulationOperand struct {
	Output              block.WorkResultOutputOrError // Output or error (o ∈ Y ∪ J)
	PayloadHash         crypto.Hash                   // Payload hash (l ∈ H)
	WorkPackageHash     crypto.Hash                   // Work-package hash (k ∈ H)
	AuthorizationOutput []byte                        // Authorization output (a ∈ Y)
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
