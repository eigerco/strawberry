package state

import (
	"crypto/ed25519"
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/time"
)

// WorkReport represents a work report in the JAM state
// TODO: The total serialized size of a work-report may be no greater than MaxWorkPackageSizeBytes.
type WorkReport struct {
	WorkPackageSpecification AvailabilitySpecification // Work-package specification (s)
	RefinementContext        RefinementContext         // Refinement context (x)
	CoreIndex                uint16                    // Core index (c) - Max value: TotalNumberOfCores
	AuthorizerHash           crypto.Hash               // HeaderHash of the authorizer (a)
	Output                   []byte                    // Output of the work report (o)
	WorkResults              []WorkResult              // Results of the evaluation of each of the items in the work-package (r) - Min value: MinWorkPackageResultsSize. Max value: MaxWorkPackageResultsSize.
}

type AvailabilitySpecification struct {
	WorkPackageHash           crypto.Hash // Hash of the work-package (h)
	AuditableWorkBundleLength uint32      // Length of the auditable work bundle (l)
	ErasureRoot               crypto.Hash // Erasure root (u) - is the root of a binary Merkle tree which functions as a commitment to all data required for the auditing of the report and for use by later workpackages should they need to retrieve any data yielded. It is thus used by assurers to verify the correctness of data they have been sent by guarantors, and it is later verified as correct by auditors.
	SegmentRoot               crypto.Hash // Segment root (e) - root of a constant-depth, left-biased and zero-hash-padded binary Merkle tree committing to the hashes of each of the exported segments of each work-item. These are used by guarantors to verify the correctness of any reconstructed segments they are called upon to import for evaluation of some later work-package.
}

// RefinementContext describes the context of the chain at the point that the report’s corresponding work-package was evaluated.
type RefinementContext struct {
	Anchor                  RefinementContextAnchor       // Historical block anchor
	LookupAnchor            RefinementContextLookupAnchor // Historical block anchor
	PrerequisiteWorkPackage *crypto.Hash                  // Prerequisite work package (p) (optional)
}

type RefinementContextAnchor struct {
	HeaderHash         crypto.Hash // HeaderHash of the anchor (a)
	PosteriorStateRoot crypto.Hash // Posterior state root (s)
	PosteriorBeefyRoot crypto.Hash // Posterior beefy root (b)
}

type RefinementContextLookupAnchor struct {
	HeaderHash crypto.Hash   // HeaderHash of the anchor (l)
	Timeslot   time.Timeslot // Timeslot (t)
}

type Assignment struct {
	WorkReport WorkReport    // Work-Report (w)
	Time       time.Timeslot // time at which work-report was reported but not yet accumulated (t)
}

type Judgements struct {
	BadWorkReports     []crypto.Hash       //  Bad work-reports (ψb) - Work-reports judged to be incorrect.
	GoodWorkReports    []crypto.Hash       //  Good work-reports (ψg) - Work-reports judged to be correct.
	WonkyWorkReports   []crypto.Hash       //  Wonky work-reports (ψw) - Work-reports whose validity is judged to be unknowable.
	OffenderValidators []ed25519.PublicKey //  Punished validators (ψp) - Validators who made a judgement found to be incorrect.
}

type CoreAssignments [TotalNumberOfCores]Assignment
