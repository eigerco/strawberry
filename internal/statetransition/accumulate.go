package statetransition

import (
	"errors"

	"github.com/eigerco/strawberry/pkg/log"

	"github.com/eigerco/strawberry/internal/block"
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/jamtime"
	"github.com/eigerco/strawberry/internal/pvm"
	"github.com/eigerco/strawberry/internal/pvm/host_call"
	"github.com/eigerco/strawberry/internal/safemath"
	"github.com/eigerco/strawberry/internal/service"
	"github.com/eigerco/strawberry/internal/state"
	"github.com/eigerco/strawberry/internal/work"
	"github.com/eigerco/strawberry/pkg/serialization/codec/jam"
)

const (
	OnTransferCost = 10
	AccumulateCost = 10
)

// AccumulationOutput (O) (eq. 12.23 v0.7.2)
type AccumulationOutput struct {
	AccumulationState state.AccumulationState    // e ∈ S
	DeferredTransfers []service.DeferredTransfer // t ∈ ⟦X⟧
	Result            *crypto.Hash               // y ∈ H?
	GasUsed           uint64                     //  u ∈ NG
	ProvidedPreimages []block.Preimage           //  p ∈ {(N_S, B)}
}

func NewAccumulator(newEntropyPool state.EntropyPool, header *block.Header, newTimeslot jamtime.Timeslot) *Accumulator {
	return &Accumulator{
		header:         header,
		newEntropyPool: newEntropyPool,
		newTimeslot:    newTimeslot,
	}
}

type Accumulator struct {
	header         *block.Header
	newEntropyPool state.EntropyPool
	newTimeslot    jamtime.Timeslot
}

// InvokePVM ΨA(U, N_T, N_S, N_G, ⟦I⟧) → O Equation (B.9)
func (a *Accumulator) InvokePVM(accState state.AccumulationState, newTime jamtime.Timeslot, serviceIndex block.ServiceId, gas uint64, accOperand []*state.AccumulationInput) (AccumulationOutput, error) {
	account := accState.ServiceState[serviceIndex]
	// s = e except s_d[s]b = e_d[s]b + [∑ r∈x] r_a
	stateWithBalance, trErr := addTransfersBalance(accState, serviceIndex, accOperand)
	if trErr != nil {
		log.VM.Error().Err(trErr).Msgf("error adding transfers balance")
		return AccumulationOutput{}, trErr
	}

	_, c := account.EncodedCodeAndMetadata()
	// if c = ∅ ∨ ∣c∣ > WC
	if c == nil || len(c) == work.MaxSizeServiceCode {
		return AccumulationOutput{AccumulationState: stateWithBalance}, nil
	}

	// I(s, s)^2
	var (
		newCtxPair pvm.AccumulateContextPair
		err        error
	)
	newCtxPair.RegularCtx, err = a.newCtx(stateWithBalance, serviceIndex)
	if err != nil {
		log.VM.Error().Err(err).Msgf("error creating context")
		return AccumulationOutput{AccumulationState: accState.Clone()}, nil
	}
	newCtxPair.ExceptionalCtx, err = a.newCtx(stateWithBalance.Clone(), serviceIndex)
	if err != nil {
		log.VM.Error().Err(err).Msgf("error creating context")
		return AccumulationOutput{AccumulationState: accState.Clone()}, nil
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
		log.VM.Error().Err(err).Msgf("error encoding arguments")
		return AccumulationOutput{AccumulationState: accState.Clone()}, nil
	}

	// F (equation B.10)
	hostCallFunc := func(hostCall uint64, gasCounter pvm.Gas, regs pvm.Registers, mem pvm.Memory, ctx pvm.AccumulateContextPair) (pvm.Gas, pvm.Registers, pvm.Memory, pvm.AccumulateContextPair, error) {
		// s = (xu)d[xs]
		currentService := ctx.RegularCtx.AccumulationState.ServiceState[serviceIndex]

		if currentService.PreimageLookup == nil {
			currentService.PreimageLookup = make(map[crypto.Hash][]byte)
		}

		var err error
		switch hostCall {
		case host_call.GasID:
			gasCounter, regs, err = host_call.GasRemaining(gasCounter, regs)
		case host_call.FetchID:
			entropy := a.newEntropyPool[0]
			gasCounter, regs, mem, err = host_call.Fetch(gasCounter, regs, mem, nil, &entropy, nil, nil, nil, nil, accOperand)
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
			regs[pvm.A0] = uint64(host_call.WHAT)
			gasCounter -= AccumulateCost
		}
		// otherwise if ϱ′ < 0
		if gasCounter < 0 {
			return 0, regs, mem, ctx, pvm.ErrOutOfGas
		}
		return gasCounter, regs, mem, ctx, err
	}

	errPanic := &pvm.ErrPanic{}
	gasUsed, ret, newCtxPair, err := pvm.InvokeWholeProgram(c, 5, pvm.UGas(gas), args, hostCallFunc, newCtxPair)
	if err != nil && (errors.Is(err, pvm.ErrOutOfGas) || errors.As(err, &errPanic)) {
		log.VM.Error().Err(err).Msgf("Program invocation failed")
		return AccumulationOutput{
			GasUsed:           uint64(gasUsed),
			AccumulationState: newCtxPair.ExceptionalCtx.AccumulationState,
			DeferredTransfers: newCtxPair.ExceptionalCtx.DeferredTransfers,
			ProvidedPreimages: newCtxPair.ExceptionalCtx.ProvidedPreimages,
			Result:            newCtxPair.ExceptionalCtx.AccumulationHash,
		}, nil
	}

	output := AccumulationOutput{
		GasUsed:           uint64(gasUsed),
		AccumulationState: newCtxPair.RegularCtx.AccumulationState,
		DeferredTransfers: newCtxPair.RegularCtx.DeferredTransfers,
		ProvidedPreimages: newCtxPair.RegularCtx.ProvidedPreimages,
		Result:            newCtxPair.RegularCtx.AccumulationHash,
	}
	// if o ∈ B ∖ H. There is no sure way to check that a byte array is a hash
	// one way would be to check the shannon entropy but this also not a guarantee, so we just limit to checking the size
	if len(ret) == crypto.HashSize {
		h := crypto.Hash(ret)
		output.Result = &h

		return output, nil
	}

	return output, nil
}

// s = e except s_d[s]b = e_d[s]b + [∑ r∈x] r_a
// x = [i S i <− i, i ∈ X] (part of eq. B.9 v0.7.1)
func addTransfersBalance(accState state.AccumulationState, serviceId block.ServiceId, operands []*state.AccumulationInput) (state.AccumulationState, error) {
	newAccState := accState.Clone()
	for _, op := range operands {
		_, val, err := op.IndexValue()
		if err != nil {
			log.VM.Error().Err(err).Msgf("Failed to get operand")
		}
		dtransfer, isTransfer := val.(service.DeferredTransfer)
		svc, serviceExists := newAccState.ServiceState[serviceId]
		if isTransfer && serviceExists {
			var ok bool
			svc.Balance, ok = safemath.Add(svc.Balance, dtransfer.Balance)
			if !ok {
				log.VM.Error().Msgf("Balance overflow when adding deferred transfer")
				return state.AccumulationState{}, safemath.ErrOverflow
			}
			newAccState.ServiceState[serviceId] = svc
		}
	}
	return newAccState, nil
}

// newCtx (B.9)
func (a *Accumulator) newCtx(u state.AccumulationState, serviceIndex block.ServiceId) (pvm.AccumulateContext, error) {
	ctx := pvm.AccumulateContext{
		ServiceId:         serviceIndex,
		AccumulationState: u,
		DeferredTransfers: []service.DeferredTransfer{},
		ProvidedPreimages: []block.Preimage{},
	}

	newServiceID, err := a.newServiceID(serviceIndex)
	if err != nil {
		return pvm.AccumulateContext{}, err
	}
	ctx.NewServiceId = service.DeriveIndex(newServiceID, u.ServiceState)
	return ctx, nil
}

func (a *Accumulator) newServiceID(serviceIndex block.ServiceId) (block.ServiceId, error) {
	hashBytes, err := jam.Marshal(struct {
		ServiceID block.ServiceId `jam:"encoding=compact"`
		Entropy   crypto.Hash
		Timeslot  jamtime.Timeslot `jam:"encoding=compact"`
	}{
		ServiceID: serviceIndex,
		Entropy:   a.newEntropyPool[0],
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
