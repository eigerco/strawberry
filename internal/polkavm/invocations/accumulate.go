package invocations

import (
	"errors"
	"github.com/eigerco/strawberry/internal/block"
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/polkavm"
	"github.com/eigerco/strawberry/internal/polkavm/host_call"
	"github.com/eigerco/strawberry/internal/polkavm/interpreter"
	"github.com/eigerco/strawberry/internal/state"
	"github.com/eigerco/strawberry/pkg/serialization"
	"github.com/eigerco/strawberry/pkg/serialization/codec"
	"github.com/eigerco/strawberry/pkg/serialization/codec/jam"
)

// InvokeAccumulate ΨA(δ†, s, g, o) the paper assumes access to the state and header variables while in go we also need to pass it explicitly as 'state' and 'header'
func InvokeAccumulate(st state.State, header *block.Header, serviceState state.ServiceState, serviceIndex block.ServiceId, gas polkavm.Gas, o []OperandResult) (x polkavm.ResultContext, r *crypto.Hash, err error) {
	s := serviceState[serviceIndex]
	serviceCode := s.PreimageLookup[s.CodeHash]
	serializer := serialization.NewSerializer(&codec.JAMCodec{})

	// if δ†[s]c = ∅
	if serviceCode == nil {
		return newCtx(st, &s, 0), nil, nil
	}

	theNewServiceID, err := newServiceID(serializer, serviceIndex, st, header)
	if err != nil {
		return newCtx(st, &s, 0), nil, err
	}
	// Equation 256: I (a ∈ A, s ∈ NS)
	ctx := newCtx(st, &s, check((theNewServiceID-(1<<8)+1)%((1<<32)-(1<<9))+(1<<8), serviceState))
	ctxPair := polkavm.ResultContextPair{
		RegularCtx:     ctx,
		ExceptionalCtx: ctx,
	}

	args, err := serializer.Encode(o)
	if err != nil {
		return newCtx(st, &s, 0), nil, err
	}

	hostCallFunc := func(hostCall uint32, gasCounter polkavm.Gas, regs polkavm.Registers, mem polkavm.Memory, ctx polkavm.ResultContextPair) (polkavm.Gas, polkavm.Registers, polkavm.Memory, polkavm.ResultContextPair, error) {
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
			gasCounter, regs, mem, ctx, err = host_call.Transfer(gasCounter, regs, mem, ctx)
		case host_call.QuitID:
			gasCounter, regs, mem, ctx, err = host_call.Quit(gasCounter, regs, mem, ctx)
		case host_call.SolicitID:
			gasCounter, regs, mem, ctx, err = host_call.Solicit(gasCounter, regs, mem, ctx, header.TimeSlotIndex)
		case host_call.ForgetID:
			gasCounter, regs, mem, ctx, err = host_call.Forget(gasCounter, regs, mem, ctx, header.TimeSlotIndex)
		default:
			regs[polkavm.A0] = uint32(polkavm.HostCallResultWhat)
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
	// if o ∈ Y ∖ H. There is no sure way to check that a byte array is a hash
	// one way would be to check the shannon entropy but this also not a guarantee, so we just limit to checking the size
	if len(ret) == crypto.HashSize {
		h := crypto.Hash(ret)
		return ctxPair.RegularCtx, &h, nil
	}

	return ctxPair.RegularCtx, nil, nil
}

func newCtx(st state.State, a *state.ServiceAccount, i block.ServiceId) polkavm.ResultContext {
	return polkavm.ResultContext{
		ServiceAccount:      a,
		AuthorizationsQueue: st.PendingAuthorizersQueues,
		ValidatorKeys:       st.ValidatorState.QueuedValidators,
		ServiceID:           i,
		DeferredTransfers:   []state.DeferredTransfer{},
		ServicesState:       nil,
		PrivilegedServices:  st.PrivilegedServices,
	}
}

func newServiceID(serializer *serialization.Serializer, serviceIndex block.ServiceId, state2 state.State, header *block.Header) (block.ServiceId, error) {
	var hashBytes []byte
	bb, err := serializer.Encode(serviceIndex)
	if err != nil {
		return 0, err
	}
	hashBytes = append(hashBytes, bb...)

	bb, err = serializer.Encode(state2.EntropyPool[0])
	if err != nil {
		return 0, err
	}
	hashBytes = append(hashBytes, bb...)

	bb, err = serializer.Encode(header.TimeSlotIndex)
	if err != nil {
		return 0, err
	}
	hashBytes = append(hashBytes, bb...)

	hData := crypto.HashData(hashBytes)
	v := block.ServiceId(0)
	jam.DeserializeTrivialNatural(hData[:], &v)
	return v, nil
}

// check Equation 260: checks if the identifier is unique across all services
func check(i block.ServiceId, serviceState state.ServiceState) block.ServiceId {
	if _, ok := serviceState[i]; !ok {
		return i
	}

	return check((i-(1<<8)+1)%((1<<32)-(1<<9))+(1<<8), serviceState)
}

// OperandResult Equation 159: O ≡ (o ∈ Y ∪ J, l ∈ H, k ∈ H, a ∈ Y)
type OperandResult struct {
	WorkPackageHash     crypto.Hash                   // Hash of the work-package (k)
	AuthorizationOutput []byte                        // Authorization output (a)
	PayloadHash         crypto.Hash                   // Hash of the payload (l)
	Output              block.WorkResultOutputOrError // Output of the work result (o) ∈ Y ∪ J: []byte or error
}

// GetOperandResults Equation 160: (M)
func GetOperandResults(serviceID block.ServiceId, w block.WorkReport) (results []OperandResult) {
	for _, r := range w.WorkResults { // Wr
		if r.ServiceId == serviceID {
			results = append(results, OperandResult{
				WorkPackageHash:     w.WorkPackageSpecification.WorkPackageHash,
				AuthorizationOutput: w.Output,
				PayloadHash:         r.PayloadHash,
				Output:              r.Output,
			})
		}
	}
	return results
}
