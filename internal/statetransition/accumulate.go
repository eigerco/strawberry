package statetransition

import (
	"errors"
	"log"
	"maps"

	"github.com/eigerco/strawberry/internal/block"
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/polkavm"
	"github.com/eigerco/strawberry/internal/polkavm/host_call"
	"github.com/eigerco/strawberry/internal/polkavm/interpreter"
	"github.com/eigerco/strawberry/internal/service"
	"github.com/eigerco/strawberry/internal/state"
	"github.com/eigerco/strawberry/pkg/serialization"
	"github.com/eigerco/strawberry/pkg/serialization/codec"
	"github.com/eigerco/strawberry/pkg/serialization/codec/jam"
)

const (
	OnTransferCost = 10
	AccumulateCost = 10
)

func NewAccumulator(state *state.State, header *block.Header) *Accumulator {
	return &Accumulator{
		header:     header,
		state:      state,
		serializer: serialization.NewSerializer(&codec.JAMCodec{}),
	}
}

type Accumulator struct {
	header     *block.Header
	state      *state.State
	serializer *serialization.Serializer
}

// InvokePVM ΨA(U, N_S , N_G, ⟦O⟧) → (U, ⟦T⟧, H?, N_G) Equation 280
func (a *Accumulator) InvokePVM(accState state.AccumulationState, serviceIndex block.ServiceId, gas uint64, accOperand []state.AccumulationOperand) (state.AccumulationState, []service.DeferredTransfer, *crypto.Hash, uint64) {
	// if d[s]c = ∅
	if accState.ServiceState[serviceIndex].Code() == nil {
		ctx, err := a.newCtx(accState, serviceIndex)
		if err != nil {
			log.Println("error creating context", "err", err)
		}
		return ctx.AccumulationState, []service.DeferredTransfer{}, nil, 0
	}

	ctx, err := a.newCtx(accState, serviceIndex)
	if err != nil {
		log.Println("error creating context", "err", err)
		return ctx.AccumulationState, []service.DeferredTransfer{}, nil, 0
	}

	// I(u, s), I(u, s)
	newCtxPair := polkavm.AccumulateContextPair{
		RegularCtx:     ctx,
		ExceptionalCtx: ctx,
	}

	// E(↕o)
	args, err := a.serializer.Encode(accOperand)
	if err != nil {
		log.Println("error encoding arguments", "err", err)
		return ctx.AccumulationState, []service.DeferredTransfer{}, nil, 0
	}

	// F (equation 283)
	hostCallFunc := func(hostCall uint32, gasCounter polkavm.Gas, regs polkavm.Registers, mem polkavm.Memory, ctx polkavm.AccumulateContextPair) (polkavm.Gas, polkavm.Registers, polkavm.Memory, polkavm.AccumulateContextPair, error) {
		// s
		currentService := accState.ServiceState[serviceIndex]
		var err error
		switch hostCall {
		case host_call.GasID:
			gasCounter, regs, err = host_call.GasRemaining(gasCounter, regs)
			ctx.RegularCtx.AccumulationState.ServiceState[ctx.RegularCtx.ServiceId] = currentService
		case host_call.LookupID:
			gasCounter, regs, mem, err = host_call.Lookup(gasCounter, regs, mem, currentService, serviceIndex, ctx.RegularCtx.AccumulationState.ServiceState)
			ctx.RegularCtx.AccumulationState.ServiceState[ctx.RegularCtx.ServiceId] = currentService
		case host_call.ReadID:
			gasCounter, regs, mem, err = host_call.Read(gasCounter, regs, mem, currentService, serviceIndex, ctx.RegularCtx.AccumulationState.ServiceState)
			ctx.RegularCtx.AccumulationState.ServiceState[ctx.RegularCtx.ServiceId] = currentService
		case host_call.WriteID:
			gasCounter, regs, mem, currentService, err = host_call.Write(gasCounter, regs, mem, currentService, serviceIndex)
			ctx.RegularCtx.AccumulationState.ServiceState[ctx.RegularCtx.ServiceId] = currentService
		case host_call.InfoID:
			gasCounter, regs, mem, err = host_call.Info(gasCounter, regs, mem, serviceIndex, ctx.RegularCtx.AccumulationState.ServiceState)
			ctx.RegularCtx.AccumulationState.ServiceState[ctx.RegularCtx.ServiceId] = currentService
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
			gasCounter, regs, mem, ctx, err = host_call.Transfer(gasCounter, regs, mem, ctx)
		case host_call.QuitID:
			gasCounter, regs, mem, ctx, err = host_call.Quit(gasCounter, regs, mem, ctx)
		case host_call.SolicitID:
			gasCounter, regs, mem, ctx, err = host_call.Solicit(gasCounter, regs, mem, ctx, a.header.TimeSlotIndex)
		case host_call.ForgetID:
			gasCounter, regs, mem, ctx, err = host_call.Forget(gasCounter, regs, mem, ctx, a.header.TimeSlotIndex)
		default:
			regs[polkavm.A0] = uint32(host_call.WHAT)
			gasCounter -= AccumulateCost
		}
		return gasCounter, regs, mem, ctx, err
	}

	remainingGas, ret, newCtxPair, err := interpreter.InvokeWholeProgram(accState.ServiceState[serviceIndex].Code(), 10, gas, args, hostCallFunc, newCtxPair)
	if err != nil {
		errPanic := &polkavm.ErrPanic{}
		if errors.Is(err, polkavm.ErrOutOfGas) || errors.As(err, &errPanic) {
			return newCtxPair.ExceptionalCtx.AccumulationState, newCtxPair.ExceptionalCtx.DeferredTransfers, nil, uint64(remainingGas)
		}
		return newCtxPair.ExceptionalCtx.AccumulationState, newCtxPair.ExceptionalCtx.DeferredTransfers, nil, uint64(remainingGas)
	}
	// if o ∈ Y ∖ H. There is no sure way to check that a byte array is a hash
	// one way would be to check the shannon entropy but this also not a guarantee, so we just limit to checking the size
	if len(ret) == crypto.HashSize {
		h := crypto.Hash(ret)
		return newCtxPair.RegularCtx.AccumulationState, newCtxPair.RegularCtx.DeferredTransfers, &h, uint64(remainingGas)
	}

	return newCtxPair.RegularCtx.AccumulationState, newCtxPair.RegularCtx.DeferredTransfers, nil, uint64(remainingGas)
}

// newCtx (281)
func (a *Accumulator) newCtx(u state.AccumulationState, serviceIndex block.ServiceId) (polkavm.AccumulateContext, error) {
	serviceState := maps.Clone(u.ServiceState)
	delete(serviceState, serviceIndex)
	ctx := polkavm.AccumulateContext{
		ServiceState: serviceState,
		ServiceId:    serviceIndex,
		AccumulationState: state.AccumulationState{
			ServiceState: map[block.ServiceId]service.ServiceAccount{
				serviceIndex: u.ServiceState[serviceIndex],
			},
			ValidatorKeys:      u.ValidatorKeys,
			WorkReportsQueue:   u.WorkReportsQueue,
			PrivilegedServices: u.PrivilegedServices,
		},
		DeferredTransfers: []service.DeferredTransfer{},
	}

	newServiceID, err := a.newServiceID(serviceIndex)
	if err != nil {
		return polkavm.AccumulateContext{}, err
	}
	ctx.NewServiceId = service.DeriveIndex(newServiceID, u.ServiceState)
	return ctx, nil
}

func (a *Accumulator) newServiceID(serviceIndex block.ServiceId) (block.ServiceId, error) {
	var hashBytes []byte
	bb, err := a.serializer.Encode(serviceIndex)
	if err != nil {
		return 0, err
	}
	hashBytes = append(hashBytes, bb...)

	bb, err = a.serializer.Encode(a.state.EntropyPool[0])
	if err != nil {
		return 0, err
	}
	hashBytes = append(hashBytes, bb...)

	bb, err = a.serializer.Encode(a.header.TimeSlotIndex)
	if err != nil {
		return 0, err
	}
	hashBytes = append(hashBytes, bb...)

	hashData := crypto.HashData(hashBytes)
	newId := block.ServiceId(0)
	jam.DeserializeTrivialNatural(hashData[:], &newId)
	return newId, nil
}