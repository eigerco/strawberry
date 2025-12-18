package interpreter

import (
	"errors"
	"math"

	"github.com/eigerco/strawberry/internal/polkavm"
)

// InvokeWholeProgram the marshalling whole-program pvm machine state-transition function: (ΨM eq. A.44 v0.7.2)
// returns remaining gas and:
// if error is nil (meaning halt or ∎) should return a result as bytes otherwise
// error as one of:
// - ErrOutOfGas (∞)
// - ErrPanic (☇)
// - ErrPageFault (F)
func InvokeWholeProgram[X any](p []byte, entryPoint uint64, initialGas polkavm.UGas, args []byte, hostFunc polkavm.HostCall[X], x X) (polkavm.UGas, []byte, X, error) {
	program, err := polkavm.ParseBlob(p)
	if err != nil {
		return 0, nil, x, polkavm.ErrPanicf(err.Error())
	}
	ram, regs, err := polkavm.InitializeStandardProgram(program, args)
	if err != nil {
		return 0, nil, x, polkavm.ErrPanicf(err.Error())
	}
	i, err := Instantiate(program.CodeAndJumpTable, entryPoint, initialGas, regs, ram)
	if err != nil {
		return 0, nil, x, polkavm.ErrPanicf(err.Error())
	}
	x1, err := InvokeHostCall(i, hostFunc, x)
	if err == nil {
		return 0, nil, x1, polkavm.ErrPanicf("abnormal program termination, program should finish with one of: halt, out-of-gas, panic or page-fault")
	}

	_, gasRemaining, regs, memory1 := i.Results()
	// u = ϱ − max(ϱ′, 0)
	gasUsed := initialGas - polkavm.UGas(max(gasRemaining, 0))

	if errors.Is(err, polkavm.ErrHalt) {
		maybeAddr := regs[polkavm.A0]
		result := make([]byte, regs[polkavm.A1])
		if maybeAddr > math.MaxUint32 {
			return gasUsed, []byte{}, x1, nil
		}
		if err := memory1.Read(uint32(maybeAddr), result); err != nil {
			// Do not return anything if registers 7 and 8 are not pointing to a valid memory page
			// (u, [], x′) if ε = ∎ ∧ Nφ′7...+φ′8 ⊄ Vμ′
			return gasUsed, []byte{}, x1, nil
		}

		// Return the memory that registers 7 and 8 are pointing to, if it's a valid memory page
		// (u, μ′φ′7⋅⋅⋅+φ′8, x′) if ε = ∎ ∧ Nφ′7⋅⋅⋅+φ′8 ⊆ Vμ′
		return gasUsed, result, x1, nil
	}
	// if ε = ∞
	if errors.Is(err, polkavm.ErrOutOfGas) {
		return gasUsed, []byte{}, x1, err
	}
	errPageFault := &polkavm.ErrPageFault{}
	if errors.As(err, &errPageFault) {
		return gasUsed, []byte{}, x1, polkavm.ErrPanicf(err.Error())
	}
	// otherwise
	return gasUsed, nil, x1, err
}

// InvokeHostCall host call invocation (ΨH eq. A.35 v0.7.2)
func InvokeHostCall[X any](
	i *Instance,
	hostCall polkavm.HostCall[X], x X,
) (X, error) {
	for {
		hostCallIndex, err := Invoke(i)
		if err != nil {
			if errors.Is(err, polkavm.ErrHostCall) {
				i.gasRemaining, i.regs, i.memory, x, err = hostCall(hostCallIndex, i.gasRemaining, i.regs, i.memory, x)
				if err != nil {
					return x, err
				}
				i.instructionCounter += 1 + polkavm.Skip(i.instructionCounter, i.bitmask)
				continue
			}

			return x, err
		}

		break
	}

	return x, nil
}

// Invoke basic definition (Ψ eq. A.1 v0.7.2)
func Invoke(i *Instance) (hostCall uint64, err error) {
	defer func() {
		if recoveredErr := recover(); recoveredErr != nil {
			err = polkavm.ErrPanicf("unexpected program termination: %v", recoveredErr)
		}
	}()
	for {
		if hostCall, err := i.step(); err != nil {
			return hostCall, err
		}
	}
}

func (i *Instance) Results() (uint64, polkavm.Gas, polkavm.Registers, polkavm.Memory) {
	return i.instructionCounter, i.gasRemaining, i.regs, i.memory
}
