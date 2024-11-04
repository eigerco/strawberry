package invocations

import (
	"errors"

	"github.com/eigerco/strawberry/internal/block"
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/polkavm"
	"github.com/eigerco/strawberry/internal/polkavm/host_call"
	"github.com/eigerco/strawberry/internal/polkavm/interpreter"
	. "github.com/eigerco/strawberry/internal/polkavm/util"
	"github.com/eigerco/strawberry/internal/state"
	"github.com/eigerco/strawberry/pkg/serialization"
	"github.com/eigerco/strawberry/pkg/serialization/codec"
	"github.com/eigerco/strawberry/pkg/serialization/codec/jam"
)

// InvokeAccumulate ΨA(δ†, s, g, o) the paper assumes access to the state and header variables while in go we also need to pass it explicitly as 'state' and 'header'
func InvokeAccumulate(currentState state.State, header *block.Header, serviceState state.ServiceState, serviceIndex block.ServiceId, gas polkavm.Gas, accOperand []state.AccumulationOperand) (x polkavm.AccumulateContext, r *crypto.Hash, err error) {
	s := serviceState[serviceIndex]
	serviceCode := s.PreimageLookup[s.CodeHash]
	serializer := serialization.NewSerializer(&codec.JAMCodec{})

	// if δ†[s]c = ∅
	if serviceCode == nil {
		return newCtx(currentState, &s, 0), nil, nil
	}

	theNewServiceID, err := newServiceID(serializer, serviceIndex, currentState, header)
	if err != nil {
		return newCtx(currentState, &s, 0), nil, err
	}
	// Equation 256: I (a ∈ A, s ∈ NS)
	ctx := newCtx(currentState, &s, Check((theNewServiceID-(Bit8)+1)%(Bit32-Bit9)+Bit8, serviceState))
	ctxPair := polkavm.AccumulateContextPair{
		RegularCtx:     ctx,
		ExceptionalCtx: ctx,
	}

	args, err := serializer.Encode(accOperand)
	if err != nil {
		return newCtx(currentState, &s, 0), nil, err
	}

	hostCallFunc := func(hostCall uint32, gasCounter polkavm.Gas, regs polkavm.Registers, mem polkavm.Memory, ctx polkavm.AccumulateContextPair) (polkavm.Gas, polkavm.Registers, polkavm.Memory, polkavm.AccumulateContextPair, error) {
		var err error
		switch hostCall {
		case host_call.GasID:
			gasCounter, regs, err = host_call.GasRemaining(gasCounter, regs)
		case host_call.LookupID:
			gasCounter, regs, mem, err = host_call.Lookup(gasCounter, regs, mem, s, serviceIndex, serviceState)
		case host_call.ReadID:
			gasCounter, regs, mem, err = host_call.Read(gasCounter, regs, mem, s, serviceIndex, serviceState)
		case host_call.WriteID:
			var s state.ServiceAccount
			gasCounter, regs, mem, s, err = host_call.Write(gasCounter, regs, mem, s, serviceIndex)
			ctx.RegularCtx.ServiceAccount = &s
		case host_call.InfoID:
			gasCounter, regs, mem, err = host_call.Info(gasCounter, regs, mem, s, serviceIndex, serviceState)
		case host_call.EmpowerID:
			gasCounter, regs, mem, ctx, err = host_call.Empower(gasCounter, regs, mem, ctx)
		case host_call.AssignID:
			gasCounter, regs, mem, ctx, err = host_call.Assign(gasCounter, regs, mem, ctx)
		case host_call.DesignateID:
			gasCounter, regs, mem, ctx, err = host_call.Designate(gasCounter, regs, mem, ctx)
		case host_call.CheckpointID:
			gasCounter, regs, mem, ctx, err = host_call.Checkpoint(gasCounter, regs, mem, ctx)
		case host_call.NewID:
			gasCounter, regs, mem, ctx, err = host_call.New(gasCounter, regs, mem, ctx)
		case host_call.UpgradeID:
			gasCounter, regs, mem, ctx, err = host_call.Upgrade(gasCounter, regs, mem, ctx)
		case host_call.TransferID:
			gasCounter, regs, mem, ctx, err = host_call.Transfer(gasCounter, regs, mem, ctx, serviceIndex, serviceState)
		case host_call.QuitID:
			gasCounter, regs, mem, ctx, err = host_call.Quit(gasCounter, regs, mem, ctx, serviceIndex, serviceState)
		case host_call.SolicitID:
			gasCounter, regs, mem, ctx, err = host_call.Solicit(gasCounter, regs, mem, ctx, header.TimeSlotIndex)
		case host_call.ForgetID:
			gasCounter, regs, mem, ctx, err = host_call.Forget(gasCounter, regs, mem, ctx, header.TimeSlotIndex)
		default:
			regs[polkavm.A0] = uint32(host_call.WHAT)
			gasCounter -= AccumulateCost
		}
		return gasCounter, regs, mem, ctx, err
	}

	var ret []byte
	_, ret, ctxPair, err = interpreter.InvokeWholeProgram(serviceCode, 10, gas, args, hostCallFunc, ctxPair)
	if err != nil {
		errPanic := &polkavm.ErrPanic{}
		if errors.Is(err, polkavm.ErrOutOfGas) || errors.As(err, &errPanic) {
			return ctxPair.ExceptionalCtx, nil, nil
		}
		return ctxPair.ExceptionalCtx, nil, err
	}
	// if accOperand ∈ Y ∖ H. There is no sure way to check that a byte array is a hash
	// one way would be to check the shannon entropy but this also not a guarantee, so we just limit to checking the size
	if len(ret) == crypto.HashSize {
		h := crypto.Hash(ret)
		return ctxPair.RegularCtx, &h, nil
	}

	return ctxPair.RegularCtx, nil, nil
}

func newCtx(currentState state.State, serviceAccount *state.ServiceAccount, serviceIndex block.ServiceId) polkavm.AccumulateContext {
	return polkavm.AccumulateContext{
		ServiceAccount:      serviceAccount,
		AuthorizationsQueue: currentState.PendingAuthorizersQueues,
		ValidatorKeys:       currentState.ValidatorState.QueuedValidators,
		ServiceID:           serviceIndex,
		DeferredTransfers:   []state.DeferredTransfer{},
		ServicesState:       make(state.ServiceState),
		PrivilegedServices:  currentState.PrivilegedServices,
	}
}

func newServiceID(serializer *serialization.Serializer, serviceIndex block.ServiceId, currentState state.State, header *block.Header) (block.ServiceId, error) {
	var hashBytes []byte
	bb, err := serializer.Encode(serviceIndex)
	if err != nil {
		return 0, err
	}
	hashBytes = append(hashBytes, bb...)

	bb, err = serializer.Encode(currentState.EntropyPool[0])
	if err != nil {
		return 0, err
	}
	hashBytes = append(hashBytes, bb...)

	bb, err = serializer.Encode(header.TimeSlotIndex)
	if err != nil {
		return 0, err
	}
	hashBytes = append(hashBytes, bb...)

	hashData := crypto.HashData(hashBytes)
	newId := block.ServiceId(0)
	jam.DeserializeTrivialNatural(hashData[:], &newId)
	return newId, nil
}
