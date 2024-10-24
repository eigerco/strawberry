package interpreter

import (
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

	memoryMap, err := polkavm.NewMemoryMap(0x1000, pp.RODataSize, pp.RWDataSize, pp.StackSize, 0)
	require.NoError(t, err)

	memory := NewMemory(memoryMap, pp.RWData, pp.ROData, nil)
	entryPoint, ok := pp.LookupExport("add_numbers")
	require.True(t, ok)

	t.Run("1 + 10 + 100 = 111", func(t *testing.T) {
		gasLimit := int64(1000)
		i := Instantiate(memory, entryPoint, gasLimit)
		i.SetReg(polkavm.RA, polkavm.VmAddressReturnToHost)
		i.SetReg(polkavm.SP, memoryMap.StackAddressHigh)
		i.SetReg(polkavm.A0, 1)
		i.SetReg(polkavm.A1, 10)
		m := NewMutator(i, pp, memoryMap)

		err = m.AddHostFunc("get_third_number", getThirdNumber)
		require.NoError(t, err)

		err = m.Execute()
		require.NoError(t, err)

		assert.Equal(t, gasLimit-int64(len(pp.Instructions)), i.GasRemaining())
		assert.Equal(t, uint32(111), i.GetReg(polkavm.A0))
	})

	t.Run("not enough gas", func(t *testing.T) {
		i := Instantiate(memory, entryPoint, 9)
		i.SetReg(polkavm.RA, polkavm.VmAddressReturnToHost)
		i.SetReg(polkavm.SP, memoryMap.StackAddressHigh)
		i.SetReg(polkavm.A0, 1)
		i.SetReg(polkavm.A1, 10)
		m := NewMutator(i, pp, memoryMap)

		err = m.AddHostFunc("get_third_number", getThirdNumber)
		require.NoError(t, err)

		err = m.Execute()
		require.ErrorIs(t, err, polkavm.ErrOutOfGas)
	})
}

func getThirdNumber(instance polkavm.Instance) error {
	instance.SetReg(polkavm.A0, 100)
	return nil
}
