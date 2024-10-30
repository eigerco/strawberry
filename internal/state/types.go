package state

import (
	"crypto/ed25519"
	"github.com/eigerco/strawberry/internal/block"
	"github.com/eigerco/strawberry/internal/common"
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/jamtime"
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

type CoreAssignments [common.TotalNumberOfCores]Assignment

type PendingAuthorizersQueues [common.TotalNumberOfCores][PendingAuthorizersQueueSize]crypto.Hash

type EntropyPool [EntropyPoolSize]crypto.Hash
type CoreAuthorizersPool [common.TotalNumberOfCores][]crypto.Hash // TODO: Maximum length per core: MaxAuthorizersPerCore

type WorkReportWithUnAccumulatedDependencies struct {
	WorkReport   block.WorkReport
	Dependencies map[crypto.Hash]struct{} // Set of Dependencies (Work-Package Hashes related to work report)
}

type AccumulationQueue [jamtime.TimeslotsPerEpoch][]WorkReportWithUnAccumulatedDependencies

type AccumulationHistory [jamtime.TimeslotsPerEpoch]map[crypto.Hash]crypto.Hash

// AccumulationOperand represents a single operand for accumulation (equation 159)
type AccumulationOperand struct {
	Output              block.WorkResultOutputOrError // Output or error (o ∈ Y ∪ J)
	PayloadHash         crypto.Hash                   // Payload hash (l ∈ H)
	WorkPackageHash     crypto.Hash                   // Work-package hash (k ∈ H)
	AuthorizationOutput []byte                        // Authorization output (a ∈ Y)
}

// Context is an intermediate value for state transition calculations
// TODO: Add relevant fields when state transitions are implemented
type Context struct {
	// Add relevant fields
	Accumulations map[uint32]crypto.Hash
}
