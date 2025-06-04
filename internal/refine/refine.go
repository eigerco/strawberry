package refine

import (
	"errors"

	"github.com/eigerco/strawberry/internal/block"
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/polkavm"
	"github.com/eigerco/strawberry/internal/polkavm/host_call"
	"github.com/eigerco/strawberry/internal/polkavm/interpreter"
	"github.com/eigerco/strawberry/internal/service"
	"github.com/eigerco/strawberry/internal/state"
	"github.com/eigerco/strawberry/internal/work"
	"github.com/eigerco/strawberry/pkg/serialization/codec/jam"
)

const (
	RefineCost = 10
)

var (
	ErrBad = errors.New("service’s code was not available for lookup") // BAD
	ErrBig = errors.New("code beyond the maximum size allowed")        // BIG
)

type RefinePVMInvoker interface {
	InvokePVM(
		itemIndex uint32,
		workPackage work.Package,
		authorizerHashOutput []byte,
		importedSegments []work.Segment,
		exportOffset uint64,
	) ([]byte, []work.Segment, uint64, error)
}

type Refine struct {
	state state.State
}

func New(state state.State) *Refine {
	return &Refine{state: state}
}

// InvokePVM ΨR(N,P,Y, ⟦⟦G⟧⟧, N) → (Y ∪ J, ⟦G⟧, N_G)
func (r *Refine) InvokePVM(
	itemIndex uint32, // i
	workPackage work.Package, // p
	authorizerHashOutput []byte, // o
	importedSegments []work.Segment, // i
	exportOffset uint64, // ς
) ([]byte, []work.Segment, uint64, error) {
	// w = p_w[i]
	w := workPackage.WorkItems[itemIndex]

	packageBytes, err := jam.Marshal(workPackage)
	if err != nil {
		return nil, nil, 0, err
	}

	// let a = E(ws, wy, H(p), px, pu)
	args, err := jam.Marshal(struct {
		ServiceIndex      block.ServiceId
		WorkPayload       []byte
		WorkPackageHash   crypto.Hash
		RefinementContext block.RefinementContext
		AuthorizerHash    crypto.Hash
	}{
		ServiceIndex:      w.ServiceId,
		WorkPayload:       w.Payload,
		WorkPackageHash:   crypto.HashData(packageBytes),
		RefinementContext: workPackage.Context,
		AuthorizerHash:    workPackage.AuthCodeHash,
	})

	// if s ∉ K(δ) ∨ Λ(δ[s], ct, c) = ∅ then (BAD, [])
	s, ok := r.state.Services[w.ServiceId]
	if !ok {
		return nil, nil, 0, ErrBad
	}

	// E(↕m, c) = Λ(δ[ws], (px)t, wc)
	encodedCodeWithMeta := s.LookupPreimage(workPackage.Context.LookupAnchor.Timeslot, w.CodeHash)
	if encodedCodeWithMeta == nil {
		return nil, nil, 0, ErrBad
	}

	var pvmCode service.CodeWithMetadata
	err = jam.Unmarshal(encodedCodeWithMeta, &pvmCode)
	if err != nil {
		return nil, nil, 0, err
	}

	// if |Λ(δ[s], ct, c)| > W_C then (BIG, [])
	if len(pvmCode.Code) > work.MaxSizeServiceCode {
		return nil, nil, 0, ErrBig
	}

	// F ∈ Ω⟨(D⟨N → M⟩, ⟦G⟧)⟩∶ (n, ϱ, ω, μ, (m, e))
	hostCall := func(hostCall uint64, gasCounter polkavm.Gas, regs polkavm.Registers, mem polkavm.Memory, ctxPair polkavm.RefineContextPair) (polkavm.Gas, polkavm.Registers, polkavm.Memory, polkavm.RefineContextPair, error) {
		switch hostCall {
		case host_call.HistoricalLookupID:
			gasCounter, regs, mem, ctxPair, err = host_call.HistoricalLookup(gasCounter, regs, mem, ctxPair, w.ServiceId, r.state.Services, workPackage.Context.LookupAnchor.Timeslot)
		case host_call.FetchID:
			zeroHash := crypto.Hash{}
			gasCounter, regs, mem, err = host_call.Fetch(gasCounter, regs, mem, &workPackage, &zeroHash, authorizerHashOutput, &itemIndex, importedSegments, nil, nil, nil)
		case host_call.ExportID:
			gasCounter, regs, mem, ctxPair, err = host_call.Export(gasCounter, regs, mem, ctxPair, exportOffset)
		case host_call.GasID:
			gasCounter, regs, err = host_call.GasRemaining(gasCounter, regs)
		case host_call.MachineID:
			gasCounter, regs, mem, ctxPair, err = host_call.Machine(gasCounter, regs, mem, ctxPair)
		case host_call.PeekID:
			gasCounter, regs, mem, ctxPair, err = host_call.Peek(gasCounter, regs, mem, ctxPair)
		case host_call.ZeroID:
			gasCounter, regs, mem, ctxPair, err = host_call.Zero(gasCounter, regs, mem, ctxPair)
		case host_call.PokeID:
			gasCounter, regs, mem, ctxPair, err = host_call.Poke(gasCounter, regs, mem, ctxPair)
		case host_call.VoidID:
			gasCounter, regs, mem, ctxPair, err = host_call.Void(gasCounter, regs, mem, ctxPair)
		case host_call.InvokeID:
			gasCounter, regs, mem, ctxPair, err = host_call.Invoke(gasCounter, regs, mem, ctxPair)
		case host_call.ExpungeID:
			gasCounter, regs, mem, ctxPair, err = host_call.Expunge(gasCounter, regs, mem, ctxPair)
		default:
			regs[polkavm.A0] = uint64(host_call.WHAT)
			gasCounter -= RefineCost

		}
		return gasCounter, regs, mem, ctxPair, nil
	}

	// (g, r, (m, e)) = ΨM(Λ(δ[w_s], (p_x)t, w_c), 0, w_g, a, F, (∅, []))∶
	remainingGas, result, ctxPair, err := interpreter.InvokeWholeProgram(pvmCode.Code, 0, polkavm.Gas(w.GasLimitRefine), args, hostCall, polkavm.RefineContextPair{
		IntegratedPVMMap: make(map[uint64]polkavm.IntegratedPVM),
		Segments:         []work.Segment{},
	})

	// if r ∈ {∞, ☇} then (r, [])
	if err != nil {
		panicErr := &polkavm.ErrPanic{}
		if errors.Is(err, polkavm.ErrOutOfGas) || errors.As(err, &panicErr) {
			return nil, nil, 0, err
		}
	}

	return result, ctxPair.Segments, uint64(remainingGas), err
}
