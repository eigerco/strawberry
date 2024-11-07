package accumulate

import (
	"github.com/eigerco/strawberry/internal/block"
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/jamtime"
	"github.com/eigerco/strawberry/internal/polkavm"
	"github.com/eigerco/strawberry/internal/safrole"
	"github.com/eigerco/strawberry/internal/service"
	"github.com/eigerco/strawberry/internal/state"
)

// AccumulationHistory ξ ∈ ⟦D⟨H → H⟩⟧E The accumulation history. one epoch worth of work reports (162)
type AccumulationHistory [jamtime.TimeslotsPerEpoch][]crypto.Hash

// AllHashes (163) {ξ ≡ x∈ξ ⋃(x)
func AllHashes(accHistory AccumulationHistory) (hh []crypto.Hash) {
	for _, h := range accHistory {
		hh = append(hh, h...)
	}
	return hh
}

// AccumulationQueue (160) ϑ ∈ ⟦⟦(W, {H})⟧⟧E
// The accumulation queue. ready (i.e. available and/or audited) but not-yet-accumulated work-reports
type AccumulationQueue [jamtime.TimeslotsPerEpoch][]WorkReportAndDependencies

type WorkReportAndDependencies struct {
	WorkReport                block.WorkReport
	UnaccumulatedDependencies []crypto.Hash // unaccumulated dependencies, a set of work-package hashes.
}

// PartitionWorkReports
// W  - The newly available work-reports
// W! - zero prerequisite work-reports (accumulated immediately)
// WQ - Those not (queued execution)
func PartitionWorkReports(workReports []block.WorkReport) ([]block.WorkReport, []block.WorkReport) {

	// (165) W! ≡ [w S w <− W, (wx)p = ∅ ∧ wl = {}]
	// (166) WQ ≡ E([D(w) S w <− W, (wx)p ≠ ∅ ∨ wl ≠ {}], {ξ )

	for _, wr := range workReports {
		if wr.RefinementContext.PrerequisiteWorkPackage == nil || len(wr.SegmentRootLookup) == 0 {
			panic("implement me")
		}
	}
	return workReports, workReports
}

// D (167) D(w) ≡ (w, {(wx)p} ∪ K(wl))
func D(w block.WorkReport) (_ block.WorkReport, hashes []crypto.Hash) {
	if w.RefinementContext.PrerequisiteWorkPackage != nil {
		hashes = append(hashes)
	}
	for k := range w.SegmentRootLookup {
		hashes = append(hashes, k)
	}
	return w, hashes
}

// EditQueue (168) E(⟦(W, {H})⟧, {H}) → ⟦(W, {H})⟧ We define the queue-editing function E, which is
// essentially a mutator function for items such as those of ϑ,
func EditQueue(workReports []WorkReportAndDependencies, hashes []crypto.Hash) []WorkReportAndDependencies {
	panic("implement me")
}

// (Q) We further define the accumulation priority queue
// function Q, which provides the sequence of work-reports which

// (P) Finally, we define the mapping function P which
// extracts the corresponding work-package hashes from a set
// of work-reports:

// PartialStateContext (174)
// U ≡ (d ∈ D⟨NS → A⟩, i ∈ ⟦K⟧V, q ∈ C⟦H⟧QHC, x ∈ (NS, NS, NS, D⟨NS → NG⟩))
type PartialStateContext struct {
	ServiceAccount           service.ServiceAccount         // d ∈ D⟨NS → A⟩, // service accounts δ (d)
	ValidatorKeys            safrole.ValidatorsData         // i ∈ ⟦K⟧V, // validator keys ι (i)
	PendingAuthorizersQueues state.PendingAuthorizersQueues // q ∈ C⟦H⟧QHC, // queue of work-reports φ (q)
	PrivilegedServices       service.PrivilegedServices     // x ∈ (NS, NS, NS, D⟨NS → NG⟩) // privileges state χ (x)
}

// ServiceHashPairs (176) B ≡ {(NS , H)}
type ServiceHashPairs []ServiceHashPair

type ServiceHashPair struct {
	ServiceId block.ServiceId
	Hash      crypto.Hash
}

// (O) the set of wrangled operand tuples,

//W∗ sequence of accumulate-able work-reports in this block

// AccumulateWorkReports (∆+) accumulates work-reports sequentially
// transforms a gas-limit, a sequence of work-reports, an
// initial partial-state and a dictionary of services enjoying
// free accumulation, into a tuple of the number of work-results accumulated,
// a posterior state-context, the resultant deferred-transfers and accumulation-output pairings:
func AccumulateWorkReports(gasLimit polkavm.Gas, workReports []block.WorkReport, ctx PartialStateContext, services map[block.ServiceId]polkavm.Gas) (uint32, PartialStateContext, []service.DeferredTransfer, ServiceHashPairs) {
	panic("implement me")
}

// AccumulateWorkReportsNonSequentially accumulates work-reports in a non-sequential, service-aggregated manner
// ∆∗(U, ⟦W⟧, D⟨NS → NG⟩) → (NG, U, ⟦T⟧, B)
func AccumulateWorkReportsNonSequentially(ctx PartialStateContext, workReports []block.WorkReport, services map[block.ServiceId]polkavm.Gas) (uint32, PartialStateContext, []service.DeferredTransfer, ServiceHashPairs) {
	panic("implement me")
}

// ∆1 The single-service accumulation function, transforms an initial state-context,
// sequence of work-reports and a service index into an alterations state-context,
// a sequence of transfers, a possible accumulation-output and
// (U, ⟦W⟧, D⟨NS → NG⟩, NS ) → (o ∈ U, t ∈ ⟦T⟧, b ∈ H?, u ∈ NG)
