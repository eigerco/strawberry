package authorization

import (
	"github.com/eigerco/strawberry/internal/common"
	"github.com/eigerco/strawberry/internal/polkavm"
	"github.com/eigerco/strawberry/internal/polkavm/host_call"
	"github.com/eigerco/strawberry/internal/polkavm/interpreter"
	"github.com/eigerco/strawberry/internal/state"
	"github.com/eigerco/strawberry/internal/work"
	"github.com/eigerco/strawberry/pkg/serialization/codec/jam"
)

const (
	isAuthorizedCost = 10
)

type EmptyContext struct{}

type Authorization struct {
	state state.State
}

// InvokePVM ΨI(P, NC) → Y ∪ J
func (a *Authorization) InvokePVM(
	workPackage work.Package, // p
	coreCode uint16, // c
) ([]byte, error) {
	// E(p, c)
	args, err := jam.Marshal(struct {
		WorkPackage work.Package
		Core        uint16
	}{
		WorkPackage: workPackage,
		Core:        coreCode,
	})
	if err != nil {
		return nil, err
	}

	// F ∈ Ω⟨{}⟩∶ (n, ϱ, ω, µ)
	hostCall := func(
		hostCall uint32,
		gasCounter polkavm.Gas,
		regs polkavm.Registers,
		mem polkavm.Memory,
		ctx EmptyContext,
	) (polkavm.Gas, polkavm.Registers, polkavm.Memory, EmptyContext, error) {
		if hostCall == host_call.GasID {
			gasCounter, regs, err = host_call.GasRemaining(gasCounter, regs)

			return gasCounter, regs, mem, ctx, err
		}

		// (▸, ϱ−10, [ω0,…,ω6, WHAT, ω8,…], µ)
		regs[polkavm.A0] = uint64(host_call.WHAT)
		gasCounter -= isAuthorizedCost

		return gasCounter, regs, mem, ctx, nil
	}

	pc, err := workPackage.GetAuthorizationCode(a.state.Services)
	if err != nil {
		return nil, err
	}

	// (g, r, ∅) = ΨM(pc, 0, GI , E(p, c), F, ∅)
	_, result, _, err := interpreter.InvokeWholeProgram(
		pc,
		0,
		common.MaxAllocatedGasIsAuthorized,
		args,
		hostCall,
		EmptyContext{},
	)

	return result, err
}
