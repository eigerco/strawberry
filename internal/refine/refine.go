package refine

import (
	"errors"

	"github.com/eigerco/strawberry/internal/block"
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/polkavm"
	"github.com/eigerco/strawberry/internal/polkavm/host_call"
	"github.com/eigerco/strawberry/internal/polkavm/interpreter"
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

type Refine struct {
	state state.State
}

// InvokePVM ΨR(H, NG, NS , H, Y, X, H, Y, ⟦G⟧, ⟦Y⟧, N) → (Y ∪ J, ⟦Y⟧)
func (r *Refine) InvokePVM(
	serviceCodePredictionHash crypto.Hash, gas uint64, serviceIndex block.ServiceId,
	workPackageHash crypto.Hash, workPayload []byte, refinementContext block.RefinementContext,
	authorizerHash crypto.Hash, authorizerHashOutput []byte, importedSegments []polkavm.Segment,
	extrinsicDataBlobs [][]byte, exportOffset uint64,
) ([]byte, []polkavm.Segment, error) {
	// let a = E(s, y, p, c, a, ↕o, ↕[↕x | x <− x])
	args, err := jam.Marshal(struct {
		ServiceIndex         block.ServiceId
		WorkPayload          []byte
		WorkPackageHash      crypto.Hash
		RefinementContext    block.RefinementContext
		AuthorizerHash       crypto.Hash
		AuthorizerHashOutput []byte
		ExtrinsicDataBlobs   [][]byte
	}{
		ServiceIndex:         serviceIndex,
		WorkPayload:          workPayload,
		WorkPackageHash:      workPackageHash,
		RefinementContext:    refinementContext,
		AuthorizerHash:       authorizerHash,
		AuthorizerHashOutput: authorizerHashOutput,
		ExtrinsicDataBlobs:   extrinsicDataBlobs, // we assume the extrinsic data is a ordered sequence
	})
	if err != nil {
		return nil, nil, err
	}

	// if s ∉ K(δ) ∨ Λ(δ[s], ct, c) = ∅ then (BAD, [])
	service, ok := r.state.Services[serviceIndex]
	if !ok {
		return nil, nil, ErrBad
	}
	code := service.LookupPreimage(refinementContext.LookupAnchor.Timeslot, serviceCodePredictionHash)
	if code == nil {
		return nil, nil, ErrBad
	}

	// if |Λ(δ[s], ct, c)| > W_C then (BIG, [])
	if len(code) > work.MaxSizeServiceCode {
		return nil, nil, ErrBig
	}

	// F ∈ Ω⟨(D⟨N → M⟩, ⟦Y⟧)⟩∶ (n, ϱ, ω, μ, (m, e))
	hostCall := func(hostCall uint32, gasCounter polkavm.Gas, regs polkavm.Registers, mem polkavm.Memory, ctxPair polkavm.RefineContextPair) (polkavm.Gas, polkavm.Registers, polkavm.Memory, polkavm.RefineContextPair, error) {
		switch hostCall {
		case host_call.HistoricalLookupID:
			gasCounter, regs, mem, ctxPair, err = host_call.HistoricalLookup(gasCounter, regs, mem, ctxPair, serviceIndex, r.state.Services, refinementContext.LookupAnchor.Timeslot)
		case host_call.ImportID:
			gasCounter, regs, mem, ctxPair, err = host_call.Import(gasCounter, regs, mem, ctxPair, importedSegments)
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

	// (g, r, (m, e)) = ΨM(Λ(δ[s], ct, c), 0, g, a, F, (∅, []))∶
	_, result, ctxPair, err := interpreter.InvokeWholeProgram(code, 0, gas, args, hostCall, polkavm.RefineContextPair{
		IntegratedPVMMap: make(map[uint64]polkavm.IntegratedPVM),
		Segments:         []polkavm.Segment{},
	})

	// if r ∈ {∞, ☇} then (r, [])
	if err != nil {
		panicErr := &polkavm.ErrPanic{}
		if errors.Is(err, polkavm.ErrOutOfGas) || errors.As(err, &panicErr) {
			return nil, nil, err
		}
	}

	return result, ctxPair.Segments, err
}
