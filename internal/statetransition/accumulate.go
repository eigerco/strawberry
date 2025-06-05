package statetransition

import (
	"errors"
	"log"

	"github.com/eigerco/strawberry/internal/jamtime"
	"github.com/eigerco/strawberry/internal/state/serialization/statekey"

	"github.com/eigerco/strawberry/internal/block"
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/polkavm"
	"github.com/eigerco/strawberry/internal/polkavm/host_call"
	"github.com/eigerco/strawberry/internal/polkavm/interpreter"
	"github.com/eigerco/strawberry/internal/service"
	"github.com/eigerco/strawberry/internal/state"
	"github.com/eigerco/strawberry/pkg/serialization/codec/jam"
)

const (
	OnTransferCost = 10
	AccumulateCost = 10
)

func NewAccumulator(state *state.State, header *block.Header, newTimeslot jamtime.Timeslot) *Accumulator {
	return &Accumulator{
		header:      header,
		state:       state,
		newTimeslot: newTimeslot,
	}
}

type Accumulator struct {
	header      *block.Header
	state       *state.State
	newTimeslot jamtime.Timeslot
}

// InvokePVM ΨA(U, N_S , N_G, ⟦O⟧) → (U, ⟦T⟧, H?, N_G) Equation (B.8)
func (a *Accumulator) InvokePVM(accState state.AccumulationState, newTime jamtime.Timeslot, serviceIndex block.ServiceId, gas uint64, accOperand []state.AccumulationOperand) (state.AccumulationState, []service.DeferredTransfer, *crypto.Hash, uint64) {
	// if ud[s]c = ∅
	if accState.ServiceState[serviceIndex].EncodedCodeAndMetadata() == nil {
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

	// E(t, s, ↕o)
	args, err := jam.Marshal(struct {
		Timeslot             jamtime.Timeslot
		ServiceID            block.ServiceId
		AccumulationOperands []state.AccumulationOperand
	}{
		Timeslot:             newTime,
		ServiceID:            serviceIndex,
		AccumulationOperands: accOperand,
	})
	if err != nil {
		log.Println("error encoding arguments", "err", err)
		return ctx.AccumulationState, []service.DeferredTransfer{}, nil, 0
	}

	// F (equation B.10)
	hostCallFunc := func(hostCall uint64, gasCounter polkavm.Gas, regs polkavm.Registers, mem polkavm.Memory, ctx polkavm.AccumulateContextPair) (polkavm.Gas, polkavm.Registers, polkavm.Memory, polkavm.AccumulateContextPair, error) {
		// s
		currentService := accState.ServiceState[serviceIndex]
		if currentService.Storage == nil {
			currentService.Storage = make(map[statekey.StateKey][]byte)
		}
		if currentService.PreimageLookup == nil {
			currentService.PreimageLookup = make(map[crypto.Hash][]byte)
		}
		if currentService.PreimageMeta == nil {
			currentService.PreimageMeta = make(map[service.PreImageMetaKey]service.PreimageHistoricalTimeslots)
		}

		var err error
		switch hostCall {
		case host_call.GasID:
			gasCounter, regs, err = host_call.GasRemaining(gasCounter, regs)
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
		case host_call.BlessID:
			gasCounter, regs, mem, ctx, err = host_call.Bless(gasCounter, regs, mem, ctx)
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
		case host_call.EjectID:
			gasCounter, regs, mem, ctx, err = host_call.Eject(gasCounter, regs, mem, ctx, a.header.TimeSlotIndex)
		case host_call.QueryID:
			gasCounter, regs, mem, ctx, err = host_call.Query(gasCounter, regs, mem, ctx)
		case host_call.SolicitID:
			gasCounter, regs, mem, ctx, err = host_call.Solicit(gasCounter, regs, mem, ctx, a.header.TimeSlotIndex)
		case host_call.ForgetID:
			gasCounter, regs, mem, ctx, err = host_call.Forget(gasCounter, regs, mem, ctx, a.header.TimeSlotIndex)
		case host_call.YieldID:
			gasCounter, regs, mem, ctx, err = host_call.Yield(gasCounter, regs, mem, ctx)
		case host_call.LogID:
			gasCounter, regs, mem = host_call.Log(gasCounter, regs, mem, nil, &serviceIndex)
		default:
			regs[polkavm.A0] = uint64(host_call.WHAT)
			gasCounter -= AccumulateCost
		}
		return gasCounter, regs, mem, ctx, err
	}

	remainingGas, ret, newCtxPair, err := interpreter.InvokeWholeProgram(accState.ServiceState[serviceIndex].EncodedCodeAndMetadata(), 5, polkavm.Gas(gas), args, hostCallFunc, newCtxPair)
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

// newCtx (B.9)
func (a *Accumulator) newCtx(u state.AccumulationState, serviceIndex block.ServiceId) (polkavm.AccumulateContext, error) {
	serviceState := u.ServiceState.Clone()
	delete(serviceState, serviceIndex)
	ctx := polkavm.AccumulateContext{
		ServiceId: serviceIndex,
		AccumulationState: state.AccumulationState{
			ServiceState: map[block.ServiceId]service.ServiceAccount{
				serviceIndex: u.ServiceState[serviceIndex],
			},
			ValidatorKeys:            u.ValidatorKeys,
			PendingAuthorizersQueues: u.PendingAuthorizersQueues,
			PrivilegedServices:       u.PrivilegedServices,
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
	hashBytes, err := jam.Marshal(struct {
		ServiceID block.ServiceId
		Entropy   crypto.Hash
		Timeslot  jamtime.Timeslot
	}{
		ServiceID: serviceIndex,
		Entropy:   a.state.EntropyPool[0],
		Timeslot:  a.header.TimeSlotIndex,
	})
	if err != nil {
		return 0, err
	}
	hashData := crypto.HashData(hashBytes)
	newId := block.ServiceId(0)
	err = jam.Unmarshal(hashData[:], &newId)
	if err != nil {
		return 0, err
	}
	return newId, nil
}
