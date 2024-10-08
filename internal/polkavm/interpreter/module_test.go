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

	memoryMap, err := polkavm.NewMemoryMap(polkavm.VmMaxPageSize, pp.RODataSize, pp.RWDataSize, pp.StackSize, pp.ROData)
	if err != nil {
		t.Fatal(err)
	}
	m, err := NewModule(pp, memoryMap)
	if err != nil {
		t.Fatal(err)
	}
	require.NoError(t, err)

	gasLimit := int64(1000)

	m.AddHostFunc("get_third_number", getThirdNumber)
	res, gasRemaining, err := m.Run("add_numbers", gasLimit, 1, 10)
	require.NoError(t, err)

	assert.Equal(t, gasLimit-int64(len(pp.Instructions)), gasRemaining)

	// 1 + 10 + 100 = 111
	assert.Equal(t, uint32(111), res)

	// not enough gas
	_, _, err = m.Run("add_numbers", 9, 1, 10)
	require.ErrorIs(t, err, errOutOfGas)
}

func getThirdNumber(args ...uint32) (uint32, error) {
	return 100, nil
}
