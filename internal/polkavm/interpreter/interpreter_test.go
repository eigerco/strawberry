package interpreter

import (
	"slices"
	"testing"

	"github.com/eigerco/strawberry/internal/polkavm"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestInstance_Execute(t *testing.T) {
	pp := &polkavm.Program{
		RODataSize: 0,
		RWDataSize: 0,
		StackSize:  4096,
		Instructions: []polkavm.Instruction{
			{Opcode: polkavm.AddImm, Imm: []uint32{4294967288}, Reg: []polkavm.Reg{polkavm.SP, polkavm.SP}, Offset: 0, Length: 3},
			{Opcode: polkavm.StoreIndirectU32, Imm: []uint32{4}, Reg: []polkavm.Reg{polkavm.RA, polkavm.SP}, Offset: 3, Length: 3},
			{Opcode: polkavm.StoreIndirectU32, Imm: []uint32{0}, Reg: []polkavm.Reg{polkavm.S0, polkavm.SP}, Offset: 6, Length: 2},
			{Opcode: polkavm.Add, Reg: []polkavm.Reg{polkavm.S0, polkavm.A1, polkavm.A0}, Offset: 8, Length: 3},
			{Opcode: polkavm.Ecalli, Imm: []uint32{0}, Offset: 11, Length: 1},
			{Opcode: polkavm.Add, Imm: nil, Reg: []polkavm.Reg{polkavm.A0, polkavm.A0, polkavm.S0}, Offset: 12, Length: 3},
			{Opcode: polkavm.LoadIndirectU32, Imm: []uint32{4}, Reg: []polkavm.Reg{polkavm.RA, polkavm.SP}, Offset: 15, Length: 3},
			{Opcode: polkavm.LoadIndirectU32, Imm: []uint32{0}, Reg: []polkavm.Reg{polkavm.S0, polkavm.SP}, Offset: 18, Length: 2},
			{Opcode: polkavm.AddImm, Imm: []uint32{8}, Reg: []polkavm.Reg{polkavm.SP, polkavm.SP}, Offset: 20, Length: 3},
			{Opcode: polkavm.JumpIndirect, Imm: []uint32{0}, Reg: []polkavm.Reg{polkavm.RA}, Offset: 23, Length: 2},
		},
		Imports: []string{"get_third_number"},
		Exports: []polkavm.ProgramExport{{TargetCodeOffset: 0, Symbol: "add_numbers"}},
	}

	memoryMap, err := polkavm.NewMemoryMap(0x1000, uint(pp.RODataSize), uint(pp.RWDataSize), uint(pp.StackSize), 0)
	require.NoError(t, err)

	memory := memoryMap.NewMemory(pp.RWData, pp.ROData, nil)

	// find add numbers export
	i := slices.IndexFunc(pp.Exports, func(e polkavm.ProgramExport) bool { return e.Symbol == "add_numbers" })
	require.True(t, i >= 0)
	entryPoint := pp.Exports[i].TargetCodeOffset
	initialRegs := polkavm.Registers{
		polkavm.RA: polkavm.VmAddressReturnToHost,
		polkavm.SP: memoryMap.StackAddressHigh,
		polkavm.A0: 1,
		polkavm.A1: 10,
	}
	hostCall := func(hostCall uint32, gasCounter polkavm.Gas, regs polkavm.Registers, mem polkavm.Memory, x nothing) (polkavm.Gas, polkavm.Registers, polkavm.Memory, nothing, error) {
		if pp.Imports[hostCall] == "get_third_number" {
			regs1 := getThirdNumber(regs)
			return gasCounter, regs1, mem, struct{}{}, nil
		}
		return gasCounter, regs, mem, struct{}{}, nil
	}
	t.Run("1 + 10 + 100 = 111", func(t *testing.T) {
		gasLimit := polkavm.Gas(1000)
		gas, regs, _, _, err := InvokeHostCall(pp, memoryMap, entryPoint, gasLimit, initialRegs, memory, hostCall, nothing{})

		require.ErrorIs(t, err, polkavm.ErrHalt)
		assert.Equal(t, uint32(111), regs[polkavm.A0])
		assert.Equal(t, gasLimit-polkavm.Gas(len(pp.Instructions)), gas)
	})

	t.Run("not enough gas", func(t *testing.T) {
		_, _, _, _, err := InvokeHostCall(pp, memoryMap, entryPoint, 9, initialRegs, memory, hostCall, nothing{})
		require.ErrorIs(t, err, polkavm.ErrOutOfGas)
	})
}

type nothing struct{}

func getThirdNumber(regs polkavm.Registers) polkavm.Registers {
	regs[polkavm.A0] = 100
	return regs
}
