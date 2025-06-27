package interpreter

import (
	"errors"

	"github.com/eigerco/strawberry/internal/polkavm"
)

// InvokeWholeProgram the marshalling whole-program pvm machine state-transition function: (ΨM eq. A.44)
// returns remaining gas and:
// if error is nil (meaning halt or ∎) should return a result as bytes otherwise
// error as one of:
// - ErrOutOfGas (∞)
// - ErrPanic (☇)
// - ErrPageFault (F)
func InvokeWholeProgram[X any](p []byte, entryPoint uint64, initialGas polkavm.Gas, args []byte, hostFunc polkavm.HostCall[X], x X) (polkavm.Gas, []byte, X, error) {
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
	if errors.Is(err, polkavm.ErrHalt) {
		_, gasRemaining, regs, memory1 := i.Results()
		// u = ϱ − max(ϱ′, 0)
		gasUsed := max(int64(initialGas)-gasRemaining, 0)
		result := make([]byte, regs[polkavm.A1])
		if err := memory1.Read(regs[polkavm.A0], result); err != nil {
			// Do not return anything if registers 7 and 8 are not pointing to a valid memory page
			// (u, [], x′) if ε = ∎ ∧ Nφ′7...+φ′8 ⊄ Vμ′
			return polkavm.Gas(gasUsed), []byte{}, x1, nil
		}

		// Return the memory that registers 7 and 8 are pointing to, if it's a valid memory page
		// (u, μ′φ′7⋅⋅⋅+φ′8, x′) if ε = ∎ ∧ Nφ′7⋅⋅⋅+φ′8 ⊆ Vμ′
		return polkavm.Gas(gasUsed), result, x1, nil
	}

	// if ε ∈ {∞, ☇}
	return 0, nil, x1, err
}

// InvokeHostCall host call invocation (ΨH eq. A.35)
func InvokeHostCall[X any](
	i *Instance,
	hostCall polkavm.HostCall[X], x X,
) (X, error) {
	for {
		hostCallIndex, err := Invoke(i)
		if err != nil {
			if errors.Is(err, polkavm.ErrHostCall) {
				var gasRemaining polkavm.Gas
				gasRemaining, i.regs, i.memory, x, err = hostCall(hostCallIndex, polkavm.Gas(i.gasRemaining), i.regs, i.memory, x)
				i.gasRemaining = int64(gasRemaining)
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

// Invoke basic definition (Ψ eq. A.1)
func Invoke(i *Instance) (uint64, error) {
	for {
		if hostCall, err := i.step(); err != nil {
			return hostCall, err
		}
	}
}

func (i *Instance) Results() (uint64, int64, polkavm.Registers, polkavm.Memory) {
	return i.instructionCounter, i.gasRemaining, i.regs, i.memory
}
