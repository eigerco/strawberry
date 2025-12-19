package authorization

import (
	"github.com/eigerco/strawberry/internal/common"
	"github.com/eigerco/strawberry/internal/pvm"
	"github.com/eigerco/strawberry/internal/pvm/host_call"
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

// InvokePVM ΨI(P, NC) → B ∪ E
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

	// F ∈ Ω⟨{}⟩∶ (n, ϱ, φ, µ)
	hostCall := func(
		hostCall uint64,
		gasCounter pvm.Gas,
		regs pvm.Registers,
		mem pvm.Memory,
		ctx EmptyContext,
	) (pvm.Gas, pvm.Registers, pvm.Memory, EmptyContext, error) {
		switch hostCall {
		case host_call.GasID:
			gasCounter, regs, err = host_call.GasRemaining(gasCounter, regs)
		case host_call.FetchID:
			gasCounter, regs, mem, err = host_call.Fetch(gasCounter, regs, mem, &workPackage, nil, nil, nil, nil, nil, nil)
		default:
			// (▸, ϱ−10, [φ0,…,φ6, WHAT, φ8,…], µ)
			regs[pvm.A0] = uint64(host_call.WHAT)
			gasCounter -= isAuthorizedCost
		}

		// otherwise if ϱ′ < 0
		if gasCounter < 0 {
			return gasCounter, regs, mem, ctx, pvm.ErrOutOfGas
		}
		return gasCounter, regs, mem, ctx, err
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
	_, result, _, err := pvm.InvokeWholeProgram(
		pvmCode.Code, // pc
		0,
		common.MaxAllocatedGasIsAuthorized,
		args,
		hostCall,
		EmptyContext{},
	)

	return result, err
}
