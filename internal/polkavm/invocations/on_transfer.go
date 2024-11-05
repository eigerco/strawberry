package invocations

import (
	"github.com/eigerco/strawberry/internal/block"
	"github.com/eigerco/strawberry/internal/polkavm"
	"github.com/eigerco/strawberry/internal/polkavm/host_call"
	"github.com/eigerco/strawberry/internal/polkavm/interpreter"
	"github.com/eigerco/strawberry/internal/service"
	"github.com/eigerco/strawberry/pkg/serialization"
	"github.com/eigerco/strawberry/pkg/serialization/codec"
)

// InvokeOnTransfer On-Transfer service-account invocation (ΨT).
// The only state alteration it facilitates are basic alteration to the storage of the subject account
func InvokeOnTransfer(serviceState service.ServiceState, serviceIndex block.ServiceId, transfers []service.DeferredTransfer) (service.ServiceAccount, error) {
	serviceAccount := serviceState[serviceIndex]
	serviceCode := serviceAccount.PreimageLookup[serviceAccount.CodeHash]
	if serviceCode == nil || len(transfers) == 0 {
		return serviceAccount, nil
	}
	var gas polkavm.Gas
	for _, transfer := range transfers {
		gas += polkavm.Gas(transfer.GasLimit)
		serviceAccount.Balance += transfer.Balance
	}
	args, err := serialization.NewSerializer(codec.NewJamCodec()).Encode(transfers)
	if err != nil {
		return serviceAccount, err
	}

	hostCallFunc := func(hostCall uint32, gasCounter polkavm.Gas, regs polkavm.Registers, mem polkavm.Memory, s service.ServiceAccount) (polkavm.Gas, polkavm.Registers, polkavm.Memory, service.ServiceAccount, error) {
		switch hostCall {
		case host_call.GasID:
			gasCounter, regs, err = host_call.GasRemaining(gasCounter, regs)
		case host_call.LookupID:
			gasCounter, regs, mem, err = host_call.Lookup(gasCounter, regs, mem, s, serviceIndex, serviceState)
		case host_call.ReadID:
			gasCounter, regs, mem, err = host_call.Read(gasCounter, regs, mem, s, serviceIndex, serviceState)
		case host_call.WriteID:
			gasCounter, regs, mem, s, err = host_call.Write(gasCounter, regs, mem, s, serviceIndex)
		case host_call.InfoID:
			gasCounter, regs, mem, err = host_call.Info(gasCounter, regs, mem, s, serviceIndex, serviceState)
		default:
			regs[polkavm.A0] = uint32(host_call.WHAT)
			gasCounter -= OnTransferCost
		}
		return gasCounter, regs, mem, s, err
	}

	_, _, x1, err := interpreter.InvokeWholeProgram(serviceCode, 15, gas, args, hostCallFunc, serviceAccount)
	return x1, err
}
