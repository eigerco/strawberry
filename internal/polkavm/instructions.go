package polkavm

import (
	"fmt"
	"math/big"
)

type InstructionCode byte

const (
	Trap        InstructionCode = 0
	Fallthrough InstructionCode = 17

	JumpIndirect InstructionCode = 19
	LoadImm      InstructionCode = 4
	LoadU8       InstructionCode = 60
	LoadI8       InstructionCode = 74
	LoadU16      InstructionCode = 76
	LoadI16      InstructionCode = 66
	LoadU32      InstructionCode = 10
	StoreU8      InstructionCode = 71
	StoreU16     InstructionCode = 69
	StoreU32     InstructionCode = 22

	LoadImmAndJump                  InstructionCode = 6
	BranchEqImm                     InstructionCode = 7
	BranchNotEqImm                  InstructionCode = 15
	BranchLessUnsignedImm           InstructionCode = 44
	BranchLessSignedImm             InstructionCode = 32
	BranchGreaterOrEqualUnsignedImm InstructionCode = 52
	BranchGreaterOrEqualSignedImm   InstructionCode = 45
	BranchLessOrEqualSignedImm      InstructionCode = 46
	BranchLessOrEqualUnsignedImm    InstructionCode = 59
	BranchGreaterSignedImm          InstructionCode = 53
	BranchGreaterUnsignedImm        InstructionCode = 50

	StoreImmIndirectU8  InstructionCode = 26
	StoreImmIndirectU16 InstructionCode = 54
	StoreImmIndirectU32 InstructionCode = 13

	StoreIndirectU8             InstructionCode = 16
	StoreIndirectU16            InstructionCode = 29
	StoreIndirectU32            InstructionCode = 3
	LoadIndirectU8              InstructionCode = 11
	LoadIndirectI8              InstructionCode = 21
	LoadIndirectU16             InstructionCode = 37
	LoadIndirectI16             InstructionCode = 33
	LoadIndirectU32             InstructionCode = 1
	AddImm                      InstructionCode = 2
	AndImm                      InstructionCode = 18
	XorImm                      InstructionCode = 31
	OrImm                       InstructionCode = 49
	MulImm                      InstructionCode = 35
	MulUpperSignedSignedImm     InstructionCode = 65
	MulUpperUnsignedUnsignedImm InstructionCode = 63
	SetLessThanUnsignedImm      InstructionCode = 27
	SetLessThanSignedImm        InstructionCode = 56
	ShiftLogicalLeftImm         InstructionCode = 9
	ShiftLogicalRightImm        InstructionCode = 14
	ShiftArithmeticRightImm     InstructionCode = 25
	NegateAndAddImm             InstructionCode = 40
	SetGreaterThanUnsignedImm   InstructionCode = 39
	SetGreaterThanSignedImm     InstructionCode = 61
	ShiftLogicalRightImmAlt     InstructionCode = 72
	ShiftArithmeticRightImmAlt  InstructionCode = 80
	ShiftLogicalLeftImmAlt      InstructionCode = 75

	CmovIfZeroImm    InstructionCode = 85
	CmovIfNotZeroImm InstructionCode = 86

	BranchEq                     InstructionCode = 24
	BranchNotEq                  InstructionCode = 30
	BranchLessUnsigned           InstructionCode = 47
	BranchLessSigned             InstructionCode = 48
	BranchGreaterOrEqualUnsigned InstructionCode = 41
	BranchGreaterOrEqualSigned   InstructionCode = 43

	Add                      InstructionCode = 8
	Sub                      InstructionCode = 20
	And                      InstructionCode = 23
	Xor                      InstructionCode = 28
	Or                       InstructionCode = 12
	Mul                      InstructionCode = 34
	MulUpperSignedSigned     InstructionCode = 67
	MulUpperUnsignedUnsigned InstructionCode = 57
	MulUpperSignedUnsigned   InstructionCode = 81
	SetLessThanUnsigned      InstructionCode = 36
	SetLessThanSigned        InstructionCode = 58
	ShiftLogicalLeft         InstructionCode = 55
	ShiftLogicalRight        InstructionCode = 51
	ShiftArithmeticRight     InstructionCode = 77
	DivUnsigned              InstructionCode = 68
	DivSigned                InstructionCode = 64
	RemUnsigned              InstructionCode = 73
	RemSigned                InstructionCode = 70

	CmovIfZero    InstructionCode = 83
	CmovIfNotZero InstructionCode = 84

	Jump InstructionCode = 5

	Ecalli InstructionCode = 78

	StoreImmU8  InstructionCode = 62
	StoreImmU16 InstructionCode = 79
	StoreImmU32 InstructionCode = 38

	MoveReg InstructionCode = 82
	Sbrk    InstructionCode = 87

	LoadImmAndJumpIndirect InstructionCode = 42
)

type Reg byte

func (r Reg) String() string {
	switch r {
	case RA:
		return "ra"
	case SP:
		return "sp"
	case T0:
		return "t0"
	case T1:
		return "t1"
	case T2:
		return "t2"
	case S0:
		return "s0"
	case S1:
		return "s1"
	case A0:
		return "a0"
	case A1:
		return "a1"
	case A2:
		return "a2"
	case A3:
		return "a3"
	case A4:
		return "a4"
	case A5:
		return "a5"
	default:
		panic("unreachable")
	}
}

const (
	RA Reg = 0
	SP Reg = 1
	T0 Reg = 2
	T1 Reg = 3
	T2 Reg = 4
	S0 Reg = 5
	S1 Reg = 6
	A0 Reg = 7
	A1 Reg = 8
	A2 Reg = 9
	A3 Reg = 10
	A4 Reg = 11
	A5 Reg = 12
)

type RawReg uint32

func (v RawReg) get() Reg {
	value := v & 0b1111
	if value > 12 {
		value = 12
	}
	switch value {
	case 0:
		return RA
	case 1:
		return SP
	case 2:
		return T0
	case 3:
		return T1
	case 4:
		return T2
	case 5:
		return S0
	case 6:
		return S1
	case 7:
		return A0
	case 8:
		return A1
	case 9:
		return A2
	case 10:
		return A3
	case 11:
		return A4
	case 12:
		return A5
	default:
		panic("unreachable")
	}
}

var (
	// Instructions with args: none
	instrNone = []InstructionCode{Trap, Fallthrough}
	// Instructions with args: reg, imm
	instrRegImm = []InstructionCode{JumpIndirect, LoadImm, LoadU8, LoadI8, LoadU16, LoadI16, LoadU32, StoreU8, StoreU16, StoreU32}
	// Instructions with args: reg, imm, offset
	instrRegImmOffset = []InstructionCode{LoadImmAndJump, BranchEqImm, BranchNotEqImm, BranchLessUnsignedImm, BranchLessSignedImm, BranchGreaterOrEqualUnsignedImm, BranchGreaterOrEqualSignedImm, BranchLessOrEqualSignedImm, BranchLessOrEqualUnsignedImm, BranchGreaterSignedImm, BranchGreaterUnsignedImm}
	// Instructions with args: reg, imm, imm
	instrRegImmImm = []InstructionCode{StoreImmIndirectU8, StoreImmIndirectU16, StoreImmIndirectU32}
	// Instructions with args: reg, reg, imm
	instrRegRegImm = []InstructionCode{StoreIndirectU8, StoreIndirectU16, StoreIndirectU32, LoadIndirectU8, LoadIndirectI8, LoadIndirectU16, LoadIndirectI16, LoadIndirectU32, AddImm, AndImm, XorImm, OrImm, MulImm, MulUpperSignedSignedImm, MulUpperUnsignedUnsignedImm, SetLessThanUnsignedImm, SetLessThanSignedImm, ShiftLogicalLeftImm, ShiftLogicalRightImm, ShiftArithmeticRightImm, NegateAndAddImm, SetGreaterThanUnsignedImm, SetGreaterThanSignedImm, ShiftLogicalRightImmAlt, ShiftArithmeticRightImmAlt, ShiftLogicalLeftImmAlt, CmovIfZeroImm, CmovIfNotZeroImm}
	// Instructions with args: reg, reg, offset
	instrRegRegOffset = []InstructionCode{BranchEq, BranchNotEq, BranchLessUnsigned, BranchLessSigned, BranchGreaterOrEqualUnsigned, BranchGreaterOrEqualSigned}
	// Instructions with args: reg, reg, reg
	instrRegRegReg = []InstructionCode{Add, Sub, And, Xor, Or, Mul, MulUpperSignedSigned, MulUpperUnsignedUnsigned, MulUpperSignedUnsigned, SetLessThanUnsigned, SetLessThanSigned, ShiftLogicalLeft, ShiftLogicalRight, ShiftArithmeticRight, DivUnsigned, DivSigned, RemUnsigned, RemSigned, CmovIfZero, CmovIfNotZero}
	// Instructions with args: offset
	instrOffset = []InstructionCode{Jump}
	// Instructions with args: imm
	instrImm = []InstructionCode{Ecalli}
	// Instructions with args: imm, imm
	instrImmImm = []InstructionCode{StoreImmU8, StoreImmU16, StoreImmU32}
	// Instructions with args: reg, reg
	instrRegReg = []InstructionCode{MoveReg, Sbrk}
	// Instructions with args: reg, reg, imm, imm
	instrRegRegImmImm = []InstructionCode{LoadImmAndJumpIndirect}
)

type LookupTable [256]LookupEntry

type LookupEntry uint32

func (t *LookupTable) get(skip uint32, aux uint32) (uint32, uint32, uint32) {
	index := getLookupIndex(skip, aux)
	return unpack(t[index])
}

func pack(imm1Bits uint32, imm1Skip uint32, imm2Bits uint32) LookupEntry {
	if imm1Bits > 0b111111 || imm2Bits > 0b111111 || imm1Skip > 0b111111 {
		panic("imm value too big")
	}
	return LookupEntry((imm1Bits) | ((imm1Skip) << 6) | ((imm2Bits) << 12))
}

func unpack(entry LookupEntry) (uint32, uint32, uint32) {
	return uint32(entry) & 0b111111, (uint32(entry) >> 6) & 0b111111, (uint32(entry) >> 12) & 0b111111
}

func getLookupIndex(skip uint32, aux uint32) uint32 {
	if skip > 0b11111 {
		panic("skip value too big")
	}
	index := skip | ((aux & 0b111) << 5)
	if index > 0xff {
		panic("index value too big")
	}
	return index
}

func BuildLookupTable(offset uint32) LookupTable {
	clamp := func(start, end, value uint32) uint32 {
		if value < start {
			return start
		} else if value > end {
			return end
		} else {
			return value
		}
	}
	cutoffForLen := func(length uint32) uint32 {
		switch length {
		case 0:
			return 32
		case 1:
			return 24
		case 2:
			return 16
		case 3:
			return 8
		case 4:
			return 0
		default:
			panic(fmt.Sprintf("unreachable: %v", length))
		}
	}

	output := LookupTable{}
	var skip uint32 = 0
	for skip <= 0b11111 {
		var aux uint32 = 0
		for aux <= 0b111 {
			imm1Length := min(4, aux)
			imm2Length := clamp(0, 4, skip-imm1Length-offset)
			imm1Bits := cutoffForLen(imm1Length)
			imm2Bits := cutoffForLen(imm2Length)
			imm1Skip := imm1Length * 8

			index := getLookupIndex(skip, aux)
			output[index] = pack(imm1Bits, imm1Skip, imm2Bits)
			aux += 1
		}
		skip += 1
	}
	return output
}

type VisitFn func(chunk *big.Int, instructionOffset, argsLength uint32) Instruction

var (
	table1        = BuildLookupTable(1)
	table2        = BuildLookupTable(2)
	lengthToShift = [256]uint32{32, 24, 16, 8}
	decodeTable   = map[InstructionCode]VisitFn{}
)

func init() {
	for _, code := range instrNone {
		decodeTable[code] = func(chunk *big.Int, instructionOffset, argsLength uint32) Instruction {
			return Instruction{
				Code:   code,
				Offset: instructionOffset,
				Length: argsLength + 1,
			}
		}
	}
	for _, code := range instrRegImm {
		decodeTable[code] = func(chunk *big.Int, instructionOffset, argsLength uint32) Instruction {
			reg, imm := readArgsRegImm(chunk, argsLength)
			return Instruction{
				Code:   code,
				Imm:    []uint32{imm},
				Reg:    []Reg{reg.get()},
				Offset: instructionOffset,
				Length: argsLength + 1,
			}
		}
	}
	for _, code := range instrRegImmOffset {
		decodeTable[code] = func(chunk *big.Int, instructionOffset, argsLength uint32) Instruction {
			reg, imm1, imm2 := readArgsRegImmOffset(chunk, instructionOffset, argsLength)
			return Instruction{
				Code:   code,
				Imm:    []uint32{imm1, imm2},
				Reg:    []Reg{reg.get()},
				Offset: instructionOffset,
				Length: argsLength + 1,
			}
		}
	}
	for _, code := range instrRegImmImm {
		decodeTable[code] = func(chunk *big.Int, instructionOffset, argsLength uint32) Instruction {
			reg, imm1, imm2 := readArgsRegImm2(chunk, argsLength)
			return Instruction{
				Code:   code,
				Imm:    []uint32{imm1, imm2},
				Reg:    []Reg{reg.get()},
				Offset: instructionOffset,
				Length: argsLength + 1,
			}
		}
	}
	for _, code := range instrRegRegImm {
		decodeTable[code] = func(chunk *big.Int, instructionOffset, argsLength uint32) Instruction {
			reg1, reg2, imm := readArgsRegs2Imm(chunk, argsLength)
			return Instruction{
				Code:   code,
				Imm:    []uint32{imm},
				Reg:    []Reg{reg1.get(), reg2.get()},
				Offset: instructionOffset,
				Length: argsLength + 1,
			}
		}
	}
	for _, code := range instrRegRegOffset {
		decodeTable[code] = func(chunk *big.Int, instructionOffset, argsLength uint32) Instruction {
			reg1, reg2, imm := readArgsRegs2Offset(chunk, instructionOffset, argsLength)
			return Instruction{
				Code:   code,
				Imm:    []uint32{imm},
				Reg:    []Reg{reg1.get(), reg2.get()},
				Offset: instructionOffset,
				Length: argsLength + 1,
			}
		}
	}
	for _, code := range instrRegRegReg {
		decodeTable[code] = func(chunk *big.Int, instructionOffset, argsLength uint32) Instruction {
			reg1, reg2, reg3 := readArgsRegs3(chunk)
			return Instruction{
				Code:   code,
				Reg:    []Reg{reg1.get(), reg2.get(), reg3.get()},
				Offset: instructionOffset,
				Length: argsLength + 1,
			}
		}
	}
	for _, code := range instrOffset {
		decodeTable[code] = func(chunk *big.Int, instructionOffset, argsLength uint32) Instruction {
			imm := readArgsOffset(chunk, instructionOffset, argsLength)
			return Instruction{
				Code:   code,
				Imm:    []uint32{imm},
				Offset: instructionOffset,
				Length: argsLength + 1,
			}
		}
	}
	for _, code := range instrImm {
		decodeTable[code] = func(chunk *big.Int, instructionOffset, argsLength uint32) Instruction {
			imm := readArgsImm(chunk, argsLength)
			return Instruction{
				Code:   code,
				Imm:    []uint32{imm},
				Offset: instructionOffset,
				Length: argsLength + 1,
			}
		}
	}
	for _, code := range instrImmImm {
		decodeTable[code] = func(chunk *big.Int, instructionOffset, argsLength uint32) Instruction {
			imm1, imm2 := readArgsImm2(chunk, argsLength)
			return Instruction{
				Code:   code,
				Imm:    []uint32{imm1, imm2},
				Offset: instructionOffset,
				Length: argsLength + 1,
			}
		}
	}
	for _, code := range instrRegReg {
		decodeTable[code] = func(chunk *big.Int, instructionOffset, argsLength uint32) Instruction {
			reg1, reg2 := readArgsRegs2(chunk)
			return Instruction{
				Code:   code,
				Reg:    []Reg{reg1.get(), reg2.get()},
				Offset: instructionOffset,
				Length: argsLength + 1,
			}
		}
	}
	for _, code := range instrRegRegImmImm {
		decodeTable[code] = func(chunk *big.Int, instructionOffset, argsLength uint32) Instruction {
			reg1, reg2, imm1, imm2 := readArgsRegs2Imm2(chunk, argsLength)
			return Instruction{
				Code:   code,
				Imm:    []uint32{imm1, imm2},
				Reg:    []Reg{reg1.get(), reg2.get()},
				Offset: instructionOffset,
				Length: argsLength + 1,
			}
		}
	}
}

func signExtendAt(value uint32, bitsToCut uint32) uint32 {
	return uint32(int32(uint32(uint64(value))<<bitsToCut) >> bitsToCut)
}

func readSimpleVarint(chunk uint32, length uint32) uint32 {
	shift := lengthToShift[length]
	return signExtendAt(chunk, shift)
}

func readArgsImm(chunk *big.Int, skip uint32) uint32 {
	return readSimpleVarint(uint32(chunk.Uint64()), skip)
}

func readArgsOffset(chunk *big.Int, instructionOffset uint32, skip uint32) uint32 {
	return instructionOffset + readArgsImm(chunk, skip)
}

func readArgsImm2(chunk *big.Int, skip uint32) (uint32, uint32) {
	imm1Bits, imm1Skip, imm2Bits := table1.get(skip, uint32(chunk.Uint64()))
	chunk = chunk.Rsh(chunk, 8)
	imm1 := signExtendAt(uint32(chunk.Uint64()), imm1Bits)
	chunk = chunk.Rsh(chunk, uint(imm1Skip))
	imm2 := signExtendAt(uint32(chunk.Uint64()), imm2Bits)
	return imm1, imm2
}

func readArgsRegImm(chunk *big.Int, skip uint32) (RawReg, uint32) {
	reg := RawReg(chunk.Uint64())
	chunk = chunk.Rsh(chunk, 8)
	_, _, immBits := table1.get(skip, 0)
	imm := signExtendAt(uint32(chunk.Uint64()), immBits)
	return reg, imm
}

func readArgsRegImm2(chunk *big.Int, skip uint32) (RawReg, uint32, uint32) {
	reg := RawReg(chunk.Uint64())
	imm1Bits, imm1Skip, imm2Bits := table1.get(skip, uint32(chunk.Uint64())>>4)
	chunk = chunk.Rsh(chunk, 8)
	imm1 := signExtendAt(uint32(chunk.Uint64()), imm1Bits)
	chunk = chunk.Rsh(chunk, uint(imm1Skip))
	imm2 := signExtendAt(uint32(chunk.Uint64()), imm2Bits)
	return reg, imm1, imm2
}

func readArgsRegImmOffset(chunk *big.Int, instructionOffset uint32, skip uint32) (RawReg, uint32, uint32) {
	reg, imm1, imm2 := readArgsRegImm2(chunk, skip)
	return reg, imm1, instructionOffset + imm2
}

func readArgsRegs2Imm2(chunk *big.Int, skip uint32) (RawReg, RawReg, uint32, uint32) {
	value := chunk.Uint64()
	reg1, reg2, imm1Aux := RawReg(value), RawReg(value>>4), value>>8

	imm1Bits, imm1Skip, imm2Bits := table2.get(skip, uint32(imm1Aux))
	chunk = chunk.Rsh(chunk, 16)
	imm1 := signExtendAt(uint32(chunk.Uint64()), imm1Bits)
	chunk = chunk.Rsh(chunk, uint(imm1Skip))
	return reg1, reg2, imm1, signExtendAt(uint32(chunk.Uint64()), imm2Bits)
}

func readArgsRegs2Imm(chunk *big.Int, skip uint32) (RawReg, RawReg, uint32) {
	chunk64 := chunk.Uint64()
	value := uint32(chunk64)
	_, _, immBits := table1.get(skip, 0)
	return RawReg(value), RawReg(value >> 4), signExtendAt(uint32(chunk64>>8), immBits)
}

func readArgsRegs2Offset(chunk *big.Int, instructionOffset uint32, skip uint32) (RawReg, RawReg, uint32) {
	reg1, reg2, imm := readArgsRegs2Imm(chunk, skip)
	return reg1, reg2, instructionOffset + imm
}

func readArgsRegs3(chunk *big.Int) (RawReg, RawReg, RawReg) {
	chunk32 := uint32(chunk.Uint64())
	return RawReg(chunk32 >> 8), RawReg(chunk32), RawReg(chunk32 >> 4)
}

func readArgsRegs2(chunk *big.Int) (RawReg, RawReg) {
	chunk32 := uint32(chunk.Uint64())
	return RawReg(chunk32), RawReg(chunk32 >> 4)
}
