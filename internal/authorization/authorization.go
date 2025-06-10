package authorization

import (
	"github.com/eigerco/strawberry/internal/common"
	"github.com/eigerco/strawberry/internal/polkavm"
	"github.com/eigerco/strawberry/internal/polkavm/host_call"
	"github.com/eigerco/strawberry/internal/polkavm/interpreter"
	"github.com/eigerco/strawberry/internal/service"
	"github.com/eigerco/strawberry/internal/state"
	"github.com/eigerco/strawberry/internal/work"
	"github.com/eigerco/strawberry/pkg/serialization/codec/jam"
)

const (
	isAuthorizedCost = 10
)

type AuthPVMInvoker interface {
	InvokePVM(workPackage work.Package, coreIndex uint16) ([]byte, error)
}

type EmptyContext struct{}

type Authorization struct {
	state state.State
}

func New(state state.State) *Authorization {
	return &Authorization{state: state}
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
		hostCall uint64,
		gasCounter polkavm.Gas,
		regs polkavm.Registers,
		mem polkavm.Memory,
		ctx EmptyContext,
	) (polkavm.Gas, polkavm.Registers, polkavm.Memory, EmptyContext, error) {
		switch hostCall {
		case host_call.GasID:
			gasCounter, regs, err = host_call.GasRemaining(gasCounter, regs)
		case host_call.FetchID:
			gasCounter, regs, mem, err = host_call.Fetch(gasCounter, regs, mem, &workPackage, nil, nil, nil, nil, nil, nil, nil)
		default:
			// (▸, ϱ−10, [ω0,…,ω6, WHAT, ω8,…], µ)
			regs[polkavm.A0] = uint64(host_call.WHAT)
			gasCounter -= isAuthorizedCost
		}

		return gasCounter, regs, mem, ctx, nil
	}

	encodedCodeWithMeta, err := workPackage.GetAuthorizationCode(a.state.Services)
	if err != nil {
		return nil, err
	}

	var pvmCode service.CodeWithMetadata
	err = jam.Unmarshal(encodedCodeWithMeta, &pvmCode)
	if err != nil {
		return nil, err
	}

	// (g, r, ∅) = ΨM(pc, 0, GI , E(p, c), F, ∅)
	_, result, _, err := interpreter.InvokeWholeProgram(
		pvmCode.Code, // pc
		0,
		common.MaxAllocatedGasIsAuthorized,
		args,
		hostCall,
		EmptyContext{},
	)

	return result, err
}
