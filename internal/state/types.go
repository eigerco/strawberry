package state

import (
	"bytes"
	"fmt"
	"maps"
	"sort"

	"github.com/eigerco/strawberry/internal/block"
	"github.com/eigerco/strawberry/internal/common"
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/crypto/ed25519"
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

// AccumulationState characterization of state components (eq. 12.16 v0.7.1)
type AccumulationState struct {
	ServiceState             service.ServiceState                               // Service accounts δ (d ∈ D⟨NS → A⟩)
	ValidatorKeys            safrole.ValidatorsData                             // Validator keys ι (i ∈ ⟦K⟧V)
	PendingAuthorizersQueues [common.TotalNumberOfCores]PendingAuthorizersQueue // Queue of authorizers ϕ (q ∈ C⟦H⟧QHC)
	ManagerServiceId         block.ServiceId                                    // (m)
	AssignedServiceIds       [common.TotalNumberOfCores]block.ServiceId         // (a)
	DesignateServiceId       block.ServiceId                                    // (v)
	CreateProtectedServiceId block.ServiceId                                    // (r)
	AmountOfGasPerServiceId  map[block.ServiceId]uint64                         // (z)
}

func (j AccumulationState) Clone() AccumulationState {
	return AccumulationState{
		ServiceState:             j.ServiceState.Clone(),
		ValidatorKeys:            j.ValidatorKeys,
		PendingAuthorizersQueues: j.PendingAuthorizersQueues,
		ManagerServiceId:         j.ManagerServiceId,
		AssignedServiceIds:       j.AssignedServiceIds,
		DesignateServiceId:       j.DesignateServiceId,
		AmountOfGasPerServiceId:  maps.Clone(j.AmountOfGasPerServiceId),
	}
}

// AccumulationOperand represents a single operand for accumulation (U) (eq. 12.13 v0.7.1)
type AccumulationOperand struct {
	WorkPackageHash   crypto.Hash                   // Work-package hash (p ∈ H)
	SegmentRoot       crypto.Hash                   // Segment root (e ∈ H)
	AuthorizationHash crypto.Hash                   // Authorization hash (a ∈ H)
	PayloadHash       crypto.Hash                   // Payload hash (y ∈ H)
	GasLimit          uint64                        `jam:"encoding=compact"` // Gas limit (g ∈ NG)
	OutputOrError     block.WorkResultOutputOrError // Output or error (l ∈ B ∪ E)
	Trace             []byte                        // Trace of the work report (t ∈ B)
}

// AccumulationInput I ≡ U ∪ X (eq. 12.15 v0.7.0)
type AccumulationInput struct {
	inner any
}

func (a *AccumulationInput) IndexValue() (index uint, value any, err error) {
	switch a.inner.(type) {
	case AccumulationOperand:
		return 0, a.inner, nil
	case service.DeferredTransfer:
		return 1, a.inner, nil
	}
	return 0, nil, jam.ErrUnsupportedEnumTypeValue
}

func (a *AccumulationInput) ValueAt(index uint) (value any, err error) {
	switch index {
	case 0:
		return AccumulationOperand{}, nil
	case 1:
		return service.DeferredTransfer{}, nil
	}

	return nil, jam.ErrUnknownEnumTypeValue
}

func (a *AccumulationInput) SetValue(value any) error {
	switch v := value.(type) {
	case AccumulationOperand:
		a.inner = v
	case service.DeferredTransfer:
		a.inner = v
	default:
		return fmt.Errorf(jam.ErrUnsupportedType, v)
	}

	return nil
}

// AccumulationOutputLog θ ∈ ⟦(NS, H)⟧ (eq. 7.4)
type AccumulationOutputLog []ServiceHashPair

type ServiceHashPair struct {
	ServiceId block.ServiceId
	Hash      crypto.Hash
}
