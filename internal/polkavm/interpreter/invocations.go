package interpreter

import (
	"errors"

	"github.com/eigerco/strawberry/internal/polkavm"
)

// InvokeWholeProgram the marshalling whole-program pvm machine state-transition function: (ΨM)
// returns remaining gas and:
// if error is nil (meaning halt or ∎) should return a result as bytes otherwise
// error as one of:
// - ErrOutOfGas (∞)
// - ErrPanic (☇)
// - ErrPageFault (F)
func InvokeWholeProgram[X any](p []byte, entryPoint uint64, initialGas uint64, args []byte, hostFunc polkavm.HostCall[X], x X) (polkavm.Gas, []byte, X, error) {
	program, err := polkavm.ParseBlob(p)
	if err != nil {
		return 0, nil, x, polkavm.ErrPanicf(err.Error())
	}
	ram, regs, err := polkavm.InitializeStandardProgram(program, args)
	if err != nil {
		return 0, nil, x, polkavm.ErrPanicf(err.Error())
	}
	i, err := Instantiate(program.CodeAndJumpTable, entryPoint, polkavm.Gas(initialGas), regs, ram)
	if err != nil {
		return 0, nil, x, polkavm.ErrPanicf(err.Error())
	}
	x1, err := InvokeHostCall(i, hostFunc, x)
	if err != nil {
		return 0, nil, x, err
	}
	_, gasRemaining, regs, memory1 := i.Results()
	result := make([]byte, regs[polkavm.A0])
	if err := memory1.Read(regs[polkavm.A1], result); err != nil {
		return 0, nil, x, err
	}

	return gasRemaining, result, x1, nil
}

// InvokeHostCall host call invocation (ΨH)
func InvokeHostCall[X any](
	i *Instance,
	hostCall polkavm.HostCall[X], x X,
) (X, error) {
	for {
		hostCallIndex, err := Invoke(i)
		if err != nil && errors.Is(err, polkavm.ErrHostCall) {
			i.gasRemaining, i.regs, i.memory, x, err = hostCall(hostCallIndex, i.gasRemaining, i.regs, i.memory, x)
			if err != nil {
				return x, err
			}
			i.instructionCounter += 1 + polkavm.Skip(i.instructionCounter, i.bitmask)
			continue
		}

		break
	}

	return x, nil
}

// Invoke basic definition (Ψ)
func Invoke(i *Instance) (uint64, error) {
	for {
		if hostCall, err := i.step(); err != nil {
			return hostCall, err
		}
	}
}

func (i *Instance) Results() (uint64, polkavm.Gas, polkavm.Registers, polkavm.Memory) {
	return i.instructionCounter, i.gasRemaining, i.regs, i.memory
}
