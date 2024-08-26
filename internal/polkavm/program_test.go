package polkavm

import (
	"embed"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
)

//go:embed testdata
var fs embed.FS

func Test_ParseBlob(t *testing.T) {
	f, err := fs.Open("testdata/example-hello-world.polkavm")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	pp, err := ParseBlob(NewReader(f.(io.ReadSeeker)))
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, uint32(0), pp.RODataSize)
	assert.Equal(t, uint32(0), pp.RWDataSize)
	assert.Equal(t, uint32(4096), pp.StackSize)
	if assert.Equal(t, 10, len(pp.Instructions)) {
		assert.Equal(t, Instruction{
			Code:   AddImm,
			Imm:    []uint32{4294967288},
			Reg:    []Reg{SP, SP},
			Offset: 0, Length: 3,
		}, pp.Instructions[0])

		assert.Equal(t, Instruction{
			Code:   StoreIndirectU32,
			Imm:    []uint32{4},
			Reg:    []Reg{RA, SP},
			Offset: 3,
			Length: 3,
		}, pp.Instructions[1])
		assert.Equal(t, Instruction{
			Code:   StoreIndirectU32,
			Imm:    []uint32{0},
			Reg:    []Reg{S0, SP},
			Offset: 6,
			Length: 2,
		}, pp.Instructions[2])
		assert.Equal(t, Instruction{
			Code:   Add,
			Reg:    []Reg{S0, A1, A0},
			Offset: 8,
			Length: 3,
		}, pp.Instructions[3])
		assert.Equal(t, Instruction{
			Code:   Ecalli,
			Imm:    []uint32{0},
			Offset: 11,
			Length: 1,
		}, pp.Instructions[4])
		assert.Equal(t, Instruction{
			Code:   Add,
			Imm:    nil,
			Reg:    []Reg{A0, A0, S0},
			Offset: 12,
			Length: 3,
		}, pp.Instructions[5])
		assert.Equal(t, Instruction{
			Code:   LoadIndirectU32,
			Imm:    []uint32{4},
			Reg:    []Reg{RA, SP},
			Offset: 15,
			Length: 3,
		}, pp.Instructions[6])
		assert.Equal(t, Instruction{
			Code:   LoadIndirectU32,
			Imm:    []uint32{0},
			Reg:    []Reg{S0, SP},
			Offset: 18,
			Length: 2,
		}, pp.Instructions[7])
		assert.Equal(t, Instruction{
			Code:   AddImm,
			Imm:    []uint32{8},
			Reg:    []Reg{SP, SP},
			Offset: 20,
			Length: 3,
		}, pp.Instructions[8])
		assert.Equal(t, Instruction{
			Code:   JumpIndirect,
			Imm:    []uint32{0},
			Reg:    []Reg{RA},
			Offset: 23,
			Length: 2,
		}, pp.Instructions[9])
	}
	assert.Equal(t, []string{"get_third_number"}, pp.Imports)
	assert.Equal(t, []ProgramExport{{0, "add_numbers"}}, pp.Exports)
}

func Test_parseBitmaskFast(t *testing.T) {
	table := []struct {
		bitmask                        []byte
		offset, nextOffset, argsLength int
	}{
		{[]byte{0b00000011, 0, 0, 0}, 0, 1, 0},
		{[]byte{0b00000101, 0, 0, 0}, 0, 2, 1},
		{[]byte{0b10000001, 0, 0, 0}, 0, 7, 6},
		{[]byte{0b00000001, 1, 0, 0}, 0, 8, 7},
		{[]byte{0b00000001, 1 << 7, 0, 0}, 0, 15, 14},
		{[]byte{0b00000001, 0, 1, 0}, 0, 16, 15},
		{[]byte{0b00000001, 0, 1 << 7, 0}, 0, 23, 22},
		{[]byte{0b00000001, 0, 0, 1}, 0, 24, 23},

		{[]byte{0b11000000, 0, 0, 0, 0}, 6, 7, 0},
		{[]byte{0b01000000, 1, 0, 0, 0}, 6, 8, 1},

		{[]byte{0b10000000, 1, 0, 0, 0}, 7, 8, 0},
		{[]byte{0b10000000, 1 << 1, 0, 0, 0}, 7, 9, 1},

		{[]byte{0, 0, 0, 0, 0b00000001}, 0, 25, 24},
		{[]byte{0, 0, 0, 0, 0b00000001}, 6, 31, 24},
		{[]byte{0, 0, 0, 0, 0b00000001}, 7, 32, 24},
	}
	for i, tc := range table {
		nextOffset, argsLength := parseBitmaskFast(tc.bitmask, tc.offset)
		nextOffsetSlow, argsLengthSlow := parseBitmaskSlow(tc.bitmask, tc.offset)

		assert.Equal(t, nextOffset, nextOffsetSlow, "index: %d", i)
		assert.Equal(t, argsLength, argsLengthSlow, "index: %d", i)

		assert.Equal(t, tc.nextOffset, nextOffset, "index: %d", i)
		assert.Equal(t, tc.argsLength, argsLength, "index: %d", i)
	}
}

//JumpIndirect, LoadImm, LoadU8, LoadI8, LoadU16, LoadI16, LoadU32, StoreU8, StoreU16, StoreU32
