package interpreter

import (
	"fmt"

	"github.com/eigerco/strawberry/internal/polkavm"
)

type module struct {
	program                  *polkavm.Program
	memoryMap                *memoryMap
	codeOffsetBySymbol       map[string]uint32
	instructionOffsetToIndex map[uint32]int
	hostFunctions            map[string]polkavm.HostFunc
}

func (m *module) AddHostFunc(s string, hostFunc polkavm.HostFunc) {
	m.hostFunctions[s] = hostFunc
}

func NewModule(program *polkavm.Program) (polkavm.Module, error) {
	codeOffsetBySymbol := map[string]uint32{}
	for _, e := range program.Exports {
		codeOffsetBySymbol[e.Symbol] = e.TargetCodeOffset
	}
	instructionOffsetToIndex := make(map[uint32]int)
	for index, inst := range program.Instructions {
		instructionOffsetToIndex[inst.Offset] = index
	}

	memoryMap, err := newMemoryMap(VmMinPageSize, program)
	if err != nil {
		return nil, err
	}
	return &module{
		program:                  program,
		memoryMap:                memoryMap,
		codeOffsetBySymbol:       codeOffsetBySymbol,
		instructionOffsetToIndex: instructionOffsetToIndex,
		hostFunctions:            make(map[string]polkavm.HostFunc),
	}, nil
}

func (m *module) Run(symbol string, gasLimit int64, args ...uint32) (result uint32, gasRemaining int64, err error) {
	if len(args) > 6 {
		return 0, gasLimit, fmt.Errorf("too many arguments, max allowed arguments: 6")
	}
	instructionOffset, ok := m.codeOffsetBySymbol[symbol]
	if !ok {
		return 0, gasLimit, fmt.Errorf("symbol %q not found", symbol)
	}

	i := &instance{
		memory: newBasicMemory(m.memoryMap, m.program.RWData),
		regs: map[polkavm.Reg]uint32{
			polkavm.SP: VmAddrUserStackHigh,
			polkavm.RA: VmAddrReturnToHost,
		},
		instructionOffset:   instructionOffset,
		offsetForBasicBlock: make(map[uint32]int),
	}
	for n, arg := range args {
		i.regs[polkavm.A0+polkavm.Reg(n)] = arg
	}
	mutator := newMutator(i, m, gasLimit)
	mutator.startBasicBlock()
	for {
		i.cycleCounter += 1
		instruction := i.instructions[i.instructionCounter]

		i.instructionOffset = instruction.Offset
		i.instructionLength = instruction.Length
		if err := instruction.StepOnce(mutator); err != nil {
			return 0, mutator.GetGasRemaining(), err
		}

		if i.returnToHost {
			break
		}
	}

	return i.regs[polkavm.A0], mutator.GetGasRemaining(), nil
}
