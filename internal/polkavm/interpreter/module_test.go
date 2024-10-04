package interpreter

import (
	. "github.com/eigerco/strawberry/internal/polkavm"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestInstance_Execute(t *testing.T) {
	pp := &Program{
		RODataSize: 0,
		RWDataSize: 0,
		StackSize:  4096,
		Instructions: []Instruction{
			{Opcode: AddImm, Imm: []uint32{4294967288}, Reg: []Reg{SP, SP}, Offset: 0, Length: 3},
			{Opcode: StoreIndirectU32, Imm: []uint32{4}, Reg: []Reg{RA, SP}, Offset: 3, Length: 3},
			{Opcode: StoreIndirectU32, Imm: []uint32{0}, Reg: []Reg{S0, SP}, Offset: 6, Length: 2},
			{Opcode: Add, Reg: []Reg{S0, A1, A0}, Offset: 8, Length: 3},
			{Opcode: Ecalli, Imm: []uint32{0}, Offset: 11, Length: 1},
			{Opcode: Add, Imm: nil, Reg: []Reg{A0, A0, S0}, Offset: 12, Length: 3},
			{Opcode: LoadIndirectU32, Imm: []uint32{4}, Reg: []Reg{RA, SP}, Offset: 15, Length: 3},
			{Opcode: LoadIndirectU32, Imm: []uint32{0}, Reg: []Reg{S0, SP}, Offset: 18, Length: 2},
			{Opcode: AddImm, Imm: []uint32{8}, Reg: []Reg{SP, SP}, Offset: 20, Length: 3},
			{Opcode: JumpIndirect, Imm: []uint32{0}, Reg: []Reg{RA}, Offset: 23, Length: 2},
		},
		Imports: []string{"get_third_number"},
		Exports: []ProgramExport{{TargetCodeOffset: 0, Symbol: "add_numbers"}},
	}

	m, err := NewModule(pp)
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
