package statetransition

import (
	"errors"
	"log"

	"github.com/eigerco/strawberry/internal/block"
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/jamtime"
	"github.com/eigerco/strawberry/internal/polkavm"
	"github.com/eigerco/strawberry/internal/polkavm/host_call"
	"github.com/eigerco/strawberry/internal/polkavm/interpreter"
	"github.com/eigerco/strawberry/internal/service"
	"github.com/eigerco/strawberry/internal/state"
	"github.com/eigerco/strawberry/internal/work"
	"github.com/eigerco/strawberry/pkg/serialization/codec/jam"
)

const (
	OnTransferCost = 10
	AccumulateCost = 10
)

// AccumulationOutput (O) (eq. 12.20 v0.7.0)
type AccumulationOutput struct {
	AccumulationState state.AccumulationState    // e ∈ S
	DeferredTransfers []service.DeferredTransfer // t ∈ ⟦X⟧
	Result            *crypto.Hash               // y ∈ H?
	GasUsed           uint64                     //  u ∈ NG
	ProvidedPreimages []polkavm.ProvidedPreimage //  p ∈ {(N_S, B)}
}

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

// InvokePVM ΨA(U, N_T, N_S, N_G, ⟦I⟧) → O Equation (B.9)
func (a *Accumulator) InvokePVM(accState state.AccumulationState, newTime jamtime.Timeslot, serviceIndex block.ServiceId, gas uint64, accOperand []state.AccumulationOperand) AccumulationOutput {
	output := AccumulationOutput{
		AccumulationState: accState.Clone(),
	}

	account := accState.ServiceState[serviceIndex]
	c := account.EncodedCodeAndMetadata()
	// if c = ∅ ∨ ∣c∣ > WC
	if c == nil || len(c) == work.MaxSizeServiceCode {
		return output
	}

	// I(u, s)^2
	var (
		newCtxPair polkavm.AccumulateContextPair
		err        error
	)
	newCtxPair.RegularCtx, err = a.newCtx(accState.Clone(), serviceIndex)
	if err != nil {
		log.Println("error creating context", "err", err)
		return output
	}
	newCtxPair.ExceptionalCtx, err = a.newCtx(accState.Clone(), serviceIndex)
	if err != nil {
		log.Println("error creating context", "err", err)
		return output
	}

	// E(t, s, ↕o)
	args, err := jam.Marshal(struct {
		Timeslot                   jamtime.Timeslot `jam:"encoding=compact"`
		ServiceID                  block.ServiceId  `jam:"encoding=compact"`
		AccumulationOperandsLength uint             `jam:"encoding=compact"`
	}{
		Timeslot:                   newTime,
		ServiceID:                  serviceIndex,
		AccumulationOperandsLength: uint(len(accOperand)),
	})
	if err != nil {
		log.Println("error encoding arguments", "err", err)
		return output
	}

	// F (equation B.10)
	hostCallFunc := func(hostCall uint64, gasCounter polkavm.Gas, regs polkavm.Registers, mem polkavm.Memory, ctx polkavm.AccumulateContextPair) (polkavm.Gas, polkavm.Registers, polkavm.Memory, polkavm.AccumulateContextPair, error) {
		// s = (xu)d[xs]
		currentService := newCtxPair.RegularCtx.AccumulationState.ServiceState[serviceIndex]

		if currentService.PreimageLookup == nil {
			currentService.PreimageLookup = make(map[crypto.Hash][]byte)
		}

		var err error
		switch hostCall {
		case host_call.GasID:
			gasCounter, regs, err = host_call.GasRemaining(gasCounter, regs)
		case host_call.FetchID:
			entropy := a.state.EntropyPool[0]
			gasCounter, regs, mem, err = host_call.Fetch(gasCounter, regs, mem, nil, &entropy, nil, nil, nil, nil, accOperand, nil)
		case host_call.ReadID:
			gasCounter, regs, mem, err = host_call.Read(gasCounter, regs, mem, currentService, serviceIndex, ctx.RegularCtx.AccumulationState.ServiceState)
			ctx.RegularCtx.AccumulationState.ServiceState[ctx.RegularCtx.ServiceId] = currentService
		case host_call.WriteID:
			gasCounter, regs, mem, currentService, err = host_call.Write(gasCounter, regs, mem, currentService, serviceIndex)
			ctx.RegularCtx.AccumulationState.ServiceState[ctx.RegularCtx.ServiceId] = currentService
		case host_call.LookupID:
			gasCounter, regs, mem, err = host_call.Lookup(gasCounter, regs, mem, currentService, serviceIndex, ctx.RegularCtx.AccumulationState.ServiceState)
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
			gasCounter, regs, mem, ctx, err = host_call.New(gasCounter, regs, mem, ctx, a.header.TimeSlotIndex)
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
		case host_call.ProvideID:
			gasCounter, regs, mem, ctx, err = host_call.Provide(gasCounter, regs, mem, ctx, serviceIndex)
		case host_call.LogID:
			gasCounter, regs, mem, err = host_call.Log(gasCounter, regs, mem, nil, &serviceIndex)
		default:
			regs[polkavm.A0] = uint64(host_call.WHAT)
			gasCounter -= AccumulateCost
		}
		return gasCounter, regs, mem, ctx, err
	}

	gasUsed, ret, newCtxPair, err := interpreter.InvokeWholeProgram(account.EncodedCodeAndMetadata(), 5, polkavm.Gas(gas), args, hostCallFunc, newCtxPair)
	if err != nil {
		output.GasUsed = uint64(gasUsed)

		errPanic := &polkavm.ErrPanic{}
		if errors.Is(err, polkavm.ErrOutOfGas) || errors.As(err, &errPanic) {
			log.Println("Program invocation failed with error:", err)
			output.AccumulationState = newCtxPair.ExceptionalCtx.AccumulationState
			output.DeferredTransfers = newCtxPair.ExceptionalCtx.DeferredTransfers
			output.ProvidedPreimages = newCtxPair.ExceptionalCtx.ProvidedPreimages

			return output
		}
		output.AccumulationState = newCtxPair.RegularCtx.AccumulationState
		output.DeferredTransfers = newCtxPair.RegularCtx.DeferredTransfers
		output.ProvidedPreimages = newCtxPair.RegularCtx.ProvidedPreimages
		// halt
		return output
	}

	output.GasUsed = uint64(gasUsed)
	output.AccumulationState = newCtxPair.RegularCtx.AccumulationState
	output.DeferredTransfers = newCtxPair.RegularCtx.DeferredTransfers
	output.ProvidedPreimages = newCtxPair.RegularCtx.ProvidedPreimages

	// if o ∈ B ∖ H. There is no sure way to check that a byte array is a hash
	// one way would be to check the shannon entropy but this also not a guarantee, so we just limit to checking the size
	if len(ret) == crypto.HashSize {
		h := crypto.Hash(ret)
		output.Result = &h

		return output
	}

	return output
}

// newCtx (B.9)
func (a *Accumulator) newCtx(u state.AccumulationState, serviceIndex block.ServiceId) (polkavm.AccumulateContext, error) {
	ctx := polkavm.AccumulateContext{
		ServiceId:         serviceIndex,
		AccumulationState: u,
		DeferredTransfers: []service.DeferredTransfer{},
		ProvidedPreimages: []polkavm.ProvidedPreimage{},
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
