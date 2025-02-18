package statetransition

import (
	"log"

	"github.com/eigerco/strawberry/internal/block"
	"github.com/eigerco/strawberry/internal/polkavm"
	"github.com/eigerco/strawberry/internal/polkavm/host_call"
	"github.com/eigerco/strawberry/internal/polkavm/interpreter"
	"github.com/eigerco/strawberry/internal/service"
	"github.com/eigerco/strawberry/pkg/serialization/codec/jam"
)

// InvokePVMOnTransfer On-Transfer service-account invocation (ΨT).
// The only state alteration it facilitates are basic alteration to the storage of the subject account
func InvokePVMOnTransfer(serviceState service.ServiceState, serviceIndex block.ServiceId, transfers []service.DeferredTransfer) service.ServiceAccount {
	serviceAccount := serviceState[serviceIndex]
	serviceCode := serviceAccount.PreimageLookup[serviceAccount.CodeHash]
	if serviceCode == nil || len(transfers) == 0 {
		return serviceAccount
	}
	var gas uint64
	for _, transfer := range transfers {
		gas += transfer.GasLimit
		serviceAccount.Balance += transfer.Balance
	}
	args, err := jam.Marshal(transfers)
	if err != nil {
		// TODO handle errors appropriately
		log.Println("error encoding PVM arguments: ", err)
	}

	hostCallFunc := func(hostCall uint64, gasCounter polkavm.Gas, regs polkavm.Registers, mem polkavm.Memory, serviceAccount service.ServiceAccount) (polkavm.Gas, polkavm.Registers, polkavm.Memory, service.ServiceAccount, error) {
		switch hostCall {
		case host_call.GasID:
			gasCounter, regs, err = host_call.GasRemaining(gasCounter, regs)
		case host_call.LookupID:
			gasCounter, regs, mem, err = host_call.Lookup(gasCounter, regs, mem, serviceAccount, serviceIndex, serviceState)
		case host_call.ReadID:
			gasCounter, regs, mem, err = host_call.Read(gasCounter, regs, mem, serviceAccount, serviceIndex, serviceState)
		case host_call.WriteID:
			gasCounter, regs, mem, serviceAccount, err = host_call.Write(gasCounter, regs, mem, serviceAccount, serviceIndex)
		case host_call.InfoID:
			gasCounter, regs, mem, err = host_call.Info(gasCounter, regs, mem, serviceIndex, serviceState)
		default:
			regs[polkavm.A0] = uint64(host_call.WHAT)
			gasCounter -= OnTransferCost
		}
		return gasCounter, regs, mem, serviceAccount, err
	}

	_, _, newServiceAccount, err := interpreter.InvokeWholeProgram(serviceCode, 10, gas, args, hostCallFunc, serviceAccount)
	if err != nil {
		// TODO handle errors appropriately
		log.Println("the virtual machine exited with an error", err)
	}
	return newServiceAccount
}
