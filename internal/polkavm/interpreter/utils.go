package interpreter

import (
	"errors"
	"slices"

	"github.com/eigerco/strawberry/internal/polkavm"
)

// InvokeWholeProgram the marshalling whole-program pvm machine state-transition function: (ΨM)
// returns remaining gas and:
// if error is nil (meaning halt or ∎) should return a result as bytes otherwise
// error as one of:
// - ErrOutOfGas (∞)
// - ErrPanic (☇)
// - ErrPageFault (F)
func InvokeWholeProgram[X any](p []byte, entryPoint uint32, gas uint64, args []byte, hostFunc polkavm.HostCall[X], x X) (polkavm.Gas, []byte, X, error) {
	program, err := polkavm.ParseBlob(p)
	if err != nil {
		return 0, nil, x, polkavm.ErrPanicf(err.Error())
	}
	ram, regs, err := polkavm.InitializeStandardProgram(program, args)
	if err != nil {
		return 0, nil, x, polkavm.ErrPanicf(err.Error())
	}
	gasRemaining, regs, memory1, x1, err := InvokeHostCall(program, entryPoint, gas, regs, ram, hostFunc, x)
	if err != nil {
		return 0, nil, x, err
	}

	result := make([]byte, regs[polkavm.A0])
	if err := memory1.Read(uint32(regs[polkavm.A1]), result); err != nil {
		return 0, nil, x, err
	}

	return gasRemaining, result, x1, nil
}

// InvokeHostCall host call invocation (ΨH)
func InvokeHostCall[X any](
	program *polkavm.Program,
	instructionCounter uint32, initialGas uint64, regs polkavm.Registers, mem polkavm.Memory,
	hostCall polkavm.HostCall[X], x X,
) (polkavm.Gas, polkavm.Registers, polkavm.Memory, X, error) {
	var (
		hostCallIndex uint32
		err           error
		gas           = polkavm.Gas(initialGas)
	)
	for {
		instructionCounter, gas, regs, mem, hostCallIndex, err = Invoke(program, instructionCounter, gas, regs, mem)
		if err != nil && errors.Is(err, polkavm.ErrHostCall) {
			gas, regs, mem, x, err = hostCall(hostCallIndex, gas, regs, mem, x)
			if err != nil {
				return gas, regs, mem, x, err
			}
			index := slices.IndexFunc(program.CodeAndJumpTable.Instructions, func(i polkavm.Instruction) bool {
				return i.Offset == instructionCounter
			})
			if index < 0 {
				return gas, regs, mem, x, polkavm.ErrPanicf("no instructions for offset")
			}
			instructionCounter += program.CodeAndJumpTable.Instructions[index].Length
			continue
		}

		break
	}

	return gas, regs, mem, x, err
}

// Invoke basic definition (Ψ)
func Invoke(
	program *polkavm.Program,
	instructionCounter uint32, gas polkavm.Gas, regs polkavm.Registers, mem polkavm.Memory,
) (uint32, polkavm.Gas, polkavm.Registers, polkavm.Memory, uint32, error) {
	i := Instantiate(instructionCounter, gas, regs, mem)
	m := NewMutator(i, program)
	m.instance.startBasicBlock(m.program)
	for {
		// single-step invocation (Ψ1)
		instruction, err := m.instance.NextInstruction()
		if err != nil {
			return i.instructionOffset, i.gasRemaining, i.regs, i.memory, 0, err
		}
		if hostCall, err := instruction.Mutate(m); err != nil {
			return i.instructionOffset, i.gasRemaining, i.regs, i.memory, hostCall, err
		}
	}
}
