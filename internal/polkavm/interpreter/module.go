package interpreter

import (
	"fmt"
	"github.com/eigerco/strawberry/internal/polkavm"
)

type Module struct {
	program       *polkavm.Program
	memoryMap     *polkavm.MemoryMap
	hostFunctions map[string]polkavm.HostFunc
}

func (m *Module) AddHostFunc(s string, hostFunc polkavm.HostFunc) {
	m.hostFunctions[s] = hostFunc
}

func NewModule(program *polkavm.Program, memoryMap *polkavm.MemoryMap) (*Module, error) {
	return &Module{
		program:       program,
		memoryMap:     memoryMap,
		hostFunctions: make(map[string]polkavm.HostFunc),
	}, nil
}

func (m *Module) Run(symbol string, gasLimit int64, args ...uint32) (result uint32, gasRemaining int64, err error) {
	if len(args) > 6 {
		return 0, gasLimit, fmt.Errorf("too many arguments, max allowed arguments: 6")
	}
	instructionOffset, ok := m.program.LookupExport(symbol)
	if !ok {
		return 0, gasLimit, fmt.Errorf("symbol %q not found", symbol)
	}

	i := m.Instantiate(instructionOffset, gasLimit)
	for n, arg := range args {
		i.SetReg(polkavm.A0+polkavm.Reg(n), arg)
	}
	mutator := NewMutator(i, m, m.memoryMap)

	if err := mutator.Execute(); err != nil {
		return 0, i.GasRemaining(), err
	}
	return i.GetReg(polkavm.A0), i.GasRemaining(), nil
}

func (m *Module) Instantiate(instructionOffset uint32, gasLimit int64) polkavm.Instance {
	return &instance{
		memory: newBasicMemory(m.memoryMap, m.program.RWData),
		regs: map[polkavm.Reg]uint32{
			polkavm.SP: polkavm.VmAddrUserStackHigh,
			polkavm.RA: polkavm.VmAddrReturnToHost,
		},
		instructionOffset:   instructionOffset,
		offsetForBasicBlock: make(map[uint32]int),
		gasRemaining:        gasLimit,
	}
}
