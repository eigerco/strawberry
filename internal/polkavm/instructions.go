package polkavm

import (
	"encoding/binary"
	"fmt"
)

type Opcode byte

const (
	Trap        Opcode = 0
	Fallthrough Opcode = 17

	JumpIndirect Opcode = 19
	LoadImm      Opcode = 4
	LoadU8       Opcode = 60
	LoadI8       Opcode = 74
	LoadU16      Opcode = 76
	LoadI16      Opcode = 66
	LoadU32      Opcode = 10
	StoreU8      Opcode = 71
	StoreU16     Opcode = 69
	StoreU32     Opcode = 22

	LoadImmAndJump                  Opcode = 6
	BranchEqImm                     Opcode = 7
	BranchNotEqImm                  Opcode = 15
	BranchLessUnsignedImm           Opcode = 44
	BranchLessSignedImm             Opcode = 32
	BranchGreaterOrEqualUnsignedImm Opcode = 52
	BranchGreaterOrEqualSignedImm   Opcode = 45
	BranchLessOrEqualSignedImm      Opcode = 46
	BranchLessOrEqualUnsignedImm    Opcode = 59
	BranchGreaterSignedImm          Opcode = 53
	BranchGreaterUnsignedImm        Opcode = 50

	StoreImmIndirectU8  Opcode = 26
	StoreImmIndirectU16 Opcode = 54
	StoreImmIndirectU32 Opcode = 13

	StoreIndirectU8             Opcode = 16
	StoreIndirectU16            Opcode = 29
	StoreIndirectU32            Opcode = 3
	LoadIndirectU8              Opcode = 11
	LoadIndirectI8              Opcode = 21
	LoadIndirectU16             Opcode = 37
	LoadIndirectI16             Opcode = 33
	LoadIndirectU32             Opcode = 1
	AddImm                      Opcode = 2
	AndImm                      Opcode = 18
	XorImm                      Opcode = 31
	OrImm                       Opcode = 49
	MulImm                      Opcode = 35
	MulUpperSignedSignedImm     Opcode = 65
	MulUpperUnsignedUnsignedImm Opcode = 63
	SetLessThanUnsignedImm      Opcode = 27
	SetLessThanSignedImm        Opcode = 56
	ShiftLogicalLeftImm         Opcode = 9
	ShiftLogicalRightImm        Opcode = 14
	ShiftArithmeticRightImm     Opcode = 25
	NegateAndAddImm             Opcode = 40
	SetGreaterThanUnsignedImm   Opcode = 39
	SetGreaterThanSignedImm     Opcode = 61
	ShiftLogicalRightImmAlt     Opcode = 72
	ShiftArithmeticRightImmAlt  Opcode = 80
	ShiftLogicalLeftImmAlt      Opcode = 75

	CmovIfZeroImm    Opcode = 85
	CmovIfNotZeroImm Opcode = 86

	BranchEq                     Opcode = 24
	BranchNotEq                  Opcode = 30
	BranchLessUnsigned           Opcode = 47
	BranchLessSigned             Opcode = 48
	BranchGreaterOrEqualUnsigned Opcode = 41
	BranchGreaterOrEqualSigned   Opcode = 43

	Add                      Opcode = 8
	Sub                      Opcode = 20
	And                      Opcode = 23
	Xor                      Opcode = 28
	Or                       Opcode = 12
	Mul                      Opcode = 34
	MulUpperSignedSigned     Opcode = 67
	MulUpperUnsignedUnsigned Opcode = 57
	MulUpperSignedUnsigned   Opcode = 81
	SetLessThanUnsigned      Opcode = 36
	SetLessThanSigned        Opcode = 58
	ShiftLogicalLeft         Opcode = 55
	ShiftLogicalRight        Opcode = 51
	ShiftArithmeticRight     Opcode = 77
	DivUnsigned              Opcode = 68
	DivSigned                Opcode = 64
	RemUnsigned              Opcode = 73
	RemSigned                Opcode = 70

	CmovIfZero    Opcode = 83
	CmovIfNotZero Opcode = 84

	Jump Opcode = 5

	Ecalli Opcode = 78

	StoreImmU8  Opcode = 62
	StoreImmU16 Opcode = 79
	StoreImmU32 Opcode = 38

	MoveReg Opcode = 82
	Sbrk    Opcode = 87

	LoadImmAndJumpIndirect Opcode = 42
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

func parseReg(v byte) Reg {
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
	instrNone = []Opcode{Trap, Fallthrough}
	// Instructions with args: reg, imm
	instrRegImm = []Opcode{JumpIndirect, LoadImm, LoadU8, LoadI8, LoadU16, LoadI16, LoadU32, StoreU8, StoreU16, StoreU32}
	// Instructions with args: reg, imm, offset
	instrRegImmOffset = []Opcode{LoadImmAndJump, BranchEqImm, BranchNotEqImm, BranchLessUnsignedImm, BranchLessSignedImm, BranchGreaterOrEqualUnsignedImm, BranchGreaterOrEqualSignedImm, BranchLessOrEqualSignedImm, BranchLessOrEqualUnsignedImm, BranchGreaterSignedImm, BranchGreaterUnsignedImm}
	// Instructions with args: reg, imm, imm
	instrRegImm2 = []Opcode{StoreImmIndirectU8, StoreImmIndirectU16, StoreImmIndirectU32}
	// Instructions with args: reg, reg, imm
	instrReg2Imm = []Opcode{StoreIndirectU8, StoreIndirectU16, StoreIndirectU32, LoadIndirectU8, LoadIndirectI8, LoadIndirectU16, LoadIndirectI16, LoadIndirectU32, AddImm, AndImm, XorImm, OrImm, MulImm, MulUpperSignedSignedImm, MulUpperUnsignedUnsignedImm, SetLessThanUnsignedImm, SetLessThanSignedImm, ShiftLogicalLeftImm, ShiftLogicalRightImm, ShiftArithmeticRightImm, NegateAndAddImm, SetGreaterThanUnsignedImm, SetGreaterThanSignedImm, ShiftLogicalRightImmAlt, ShiftArithmeticRightImmAlt, ShiftLogicalLeftImmAlt, CmovIfZeroImm, CmovIfNotZeroImm}
	// Instructions with args: reg, reg, offset
	instrReg2Offset = []Opcode{BranchEq, BranchNotEq, BranchLessUnsigned, BranchLessSigned, BranchGreaterOrEqualUnsigned, BranchGreaterOrEqualSigned}
	// Instructions with args: reg, reg, reg
	instrReg3 = []Opcode{Add, Sub, And, Xor, Or, Mul, MulUpperSignedSigned, MulUpperUnsignedUnsigned, MulUpperSignedUnsigned, SetLessThanUnsigned, SetLessThanSigned, ShiftLogicalLeft, ShiftLogicalRight, ShiftArithmeticRight, DivUnsigned, DivSigned, RemUnsigned, RemSigned, CmovIfZero, CmovIfNotZero}
	// Instructions with args: offset
	instrOffset = []Opcode{Jump}
	// Instructions with args: imm
	instrImm = []Opcode{Ecalli}
	// Instructions with args: imm, imm
	instrImm2 = []Opcode{StoreImmU8, StoreImmU16, StoreImmU32}
	// Instructions with args: reg, reg
	instrRegReg = []Opcode{MoveReg, Sbrk}
	// Instructions with args: reg, reg, imm, imm
	instrReg2Imm2 = []Opcode{LoadImmAndJumpIndirect}
)

type InstrParseArgFunc func(chunk []byte, instructionOffset, argsLength uint32) ([]Reg, []uint32)

var parseArgsTable = map[Opcode]InstrParseArgFunc{}

func init() {
	for _, code := range instrNone {
		parseArgsTable[code] = parseArgsNone
	}
	for _, code := range instrRegImm {
		parseArgsTable[code] = parseArgsRegImm
	}
	for _, code := range instrRegImmOffset {
		parseArgsTable[code] = parseArgsRegImmOffset
	}
	for _, code := range instrRegImm2 {
		parseArgsTable[code] = parseArgsRegImm2
	}
	for _, code := range instrReg2Imm {
		parseArgsTable[code] = parseArgsRegs2Imm
	}
	for _, code := range instrReg2Offset {
		parseArgsTable[code] = parseArgsRegs2Offset
	}
	for _, code := range instrReg3 {
		parseArgsTable[code] = parseArgsRegs3
	}
	for _, code := range instrOffset {
		parseArgsTable[code] = parseArgsImmOffset
	}
	for _, code := range instrImm {
		parseArgsTable[code] = parseArgsImm
	}
	for _, code := range instrImm2 {
		parseArgsTable[code] = parseArgsImm2
	}
	for _, code := range instrRegReg {
		parseArgsTable[code] = parseArgsRegs2
	}
	for _, code := range instrReg2Imm2 {
		parseArgsTable[code] = parseArgsRegs2Imm2
	}
}

func clamp(start, end, value uint32) uint32 {
	if value < start {
		return start
	} else if value > end {
		return end
	} else {
		return value
	}
}

func sext(value uint32, length uint32) uint32 {
	switch length {
	case 0:
		return 0
	case 1:
		return uint32(int32(int8(uint8(value))))
	case 2:
		return uint32(int32(int16(uint16(value))))
	case 3:
		return uint32((int32(value << 8)) >> 8)
	case 4:
		return value
	default:
		panic("unreachable")
	}
}
func read(slice []byte, offset, length uint32) uint32 {
	slice = slice[offset : offset+length]
	switch length {
	case 0:
		return 0
	case 1:
		return uint32(slice[0])
	case 2:
		return uint32(binary.LittleEndian.Uint16(slice[:1])) // u16::from_le_bytes([slice[0], slice[1]]) as u32
	case 3:
		return binary.LittleEndian.Uint32([]byte{slice[0], slice[1], slice[2], 0})
	case 4:
		return binary.LittleEndian.Uint32([]byte{slice[0], slice[1], slice[2], slice[3]})
	default:
		panic("unreachable")
	}
}

func parseArgsImm(code []byte, _, skip uint32) ([]Reg, []uint32) {
	immLength := min(4, skip)
	return nil, []uint32{sext(read(code, 0, immLength), immLength)}
}

func parseArgsImmOffset(code []byte, instructionOffset, skip uint32) ([]Reg, []uint32) {
	_, imm := parseArgsImm(code, instructionOffset, skip)
	return nil, []uint32{instructionOffset + imm[0]}
}

func parseArgsImm2(code []byte, _, skip uint32) ([]Reg, []uint32) {
	imm1Length := min(4, uint32(code[0])&0b111)
	imm2Length := clamp(0, 4, skip-imm1Length-1)
	imm1 := sext(read(code, 1, imm1Length), imm1Length)
	imm2 := sext(read(code, 1+imm1Length, imm2Length), imm2Length)
	return nil, []uint32{imm1, imm2}
}

func parseArgsNone(_ []byte, _, _ uint32) ([]Reg, []uint32) {
	return nil, nil
}

func parseArgsRegImm(code []byte, _, skip uint32) ([]Reg, []uint32) {
	reg := min(12, code[0]&0b1111)
	immLength := clamp(0, 4, skip-1)
	imm := sext(read(code, 1, immLength), immLength)
	return []Reg{parseReg(reg)}, []uint32{imm}
}

func parseArgsRegImmOffset(code []byte, instructionOffset, skip uint32) ([]Reg, []uint32) {
	regs, imm := parseArgsRegImm2(code, instructionOffset, skip)
	return regs, []uint32{imm[0], instructionOffset + imm[1]}
}

func parseArgsRegImm2(code []byte, _, skip uint32) ([]Reg, []uint32) {
	reg := min(12, code[0]&0b1111)
	imm1Length := min(4, uint32(code[0]>>4)&0b111)
	imm2Length := clamp(0, 4, skip-imm1Length-1)
	imm1 := sext(read(code, 1, imm1Length), imm1Length)
	imm2 := sext(read(code, 1+imm1Length, imm2Length), imm2Length)
	return []Reg{parseReg(reg)}, []uint32{imm1, imm2}
}

func parseArgsRegs2Imm2(code []byte, _, skip uint32) ([]Reg, []uint32) {
	reg1 := min(12, code[0]&0b1111)
	reg2 := min(12, code[0]>>4)
	imm1Length := min(4, uint32(code[1])&0b111)
	imm2Length := clamp(0, 4, skip-imm1Length-2)
	imm1 := sext(read(code, 2, imm1Length), imm1Length)
	imm2 := sext(read(code, 2+imm1Length, imm2Length), imm2Length)
	return []Reg{parseReg(reg1), parseReg(reg2)}, []uint32{imm1, imm2}
}
func parseArgsRegs2Imm(code []byte, _, skip uint32) ([]Reg, []uint32) {
	immLength := clamp(0, 4, uint32(skip)-1)
	imm := sext(read(code, 1, immLength), immLength)
	return []Reg{
		parseReg(min(12, code[0]&0b1111)),
		parseReg(min(12, code[0]>>4)),
	}, []uint32{imm}
}

func parseArgsRegs3(code []byte, _, _ uint32) ([]Reg, []uint32) {
	return []Reg{
		parseReg(min(12, code[1]&0b1111)),
		parseReg(min(12, code[0]&0b1111)),
		parseReg(min(12, code[0]>>4)),
	}, nil
}

func parseArgsRegs2(code []byte, _, _ uint32) ([]Reg, []uint32) {
	return []Reg{parseReg(min(12, code[0]&0b1111)), parseReg(min(12, code[0]>>4))}, nil
}

func parseArgsRegs2Offset(code []byte, instructionOffset, skip uint32) ([]Reg, []uint32) {
	regs, imm := parseArgsRegs2Imm(code, instructionOffset, skip)
	return regs, []uint32{instructionOffset + imm[0]}
}

type Instruction struct {
	Opcode Opcode
	Imm    []uint32
	Reg    []Reg
	Offset uint32
	Length uint32
}

func (i *Instruction) StepOnce(mutator Mutator) error {
	switch i.Opcode {
	case Trap:
		return mutator.Trap()
	case Fallthrough:
		mutator.Fallthrough()
	case JumpIndirect:
		return mutator.JumpIndirect(i.Reg[0], i.Imm[0])
	case LoadImm:
		mutator.LoadImm(i.Reg[0], i.Imm[0])
	case LoadU8:
		return mutator.LoadU8(i.Reg[0], i.Imm[0])
	case LoadI8:
		return mutator.LoadI8(i.Reg[0], i.Imm[0])
	case LoadU16:
		return mutator.LoadU16(i.Reg[0], i.Imm[0])
	case LoadI16:
		return mutator.LoadI16(i.Reg[0], i.Imm[0])
	case LoadU32:
		return mutator.LoadU32(i.Reg[0], i.Imm[0])
	case StoreU8:
		return mutator.StoreU8(i.Reg[0], i.Imm[0])
	case StoreU16:
		return mutator.StoreU16(i.Reg[0], i.Imm[0])
	case StoreU32:
		return mutator.StoreU32(i.Reg[0], i.Imm[0])
	case LoadImmAndJump:
		mutator.LoadImmAndJump(i.Reg[0], i.Imm[0], i.Imm[1])
	case BranchEqImm:
		mutator.BranchEqImm(i.Reg[0], i.Imm[0], i.Imm[1])
	case BranchNotEqImm:
		mutator.BranchNotEqImm(i.Reg[0], i.Imm[0], i.Imm[1])
	case BranchLessUnsignedImm:
		mutator.BranchLessUnsignedImm(i.Reg[0], i.Imm[0], i.Imm[1])
	case BranchLessSignedImm:
		mutator.BranchLessSignedImm(i.Reg[0], i.Imm[0], i.Imm[1])
	case BranchGreaterOrEqualUnsignedImm:
		mutator.BranchGreaterOrEqualUnsignedImm(i.Reg[0], i.Imm[0], i.Imm[1])
	case BranchGreaterOrEqualSignedImm:
		mutator.BranchGreaterOrEqualSignedImm(i.Reg[0], i.Imm[0], i.Imm[1])
	case BranchLessOrEqualSignedImm:
		mutator.BranchLessOrEqualSignedImm(i.Reg[0], i.Imm[0], i.Imm[1])
	case BranchLessOrEqualUnsignedImm:
		mutator.BranchLessOrEqualUnsignedImm(i.Reg[0], i.Imm[0], i.Imm[1])
	case BranchGreaterSignedImm:
		mutator.BranchGreaterSignedImm(i.Reg[0], i.Imm[0], i.Imm[1])
	case BranchGreaterUnsignedImm:
		mutator.BranchGreaterUnsignedImm(i.Reg[0], i.Imm[0], i.Imm[1])
	case StoreImmIndirectU8:
		return mutator.StoreImmIndirectU8(i.Reg[0], i.Imm[0], i.Imm[1])
	case StoreImmIndirectU16:
		return mutator.StoreImmIndirectU16(i.Reg[0], i.Imm[0], i.Imm[1])
	case StoreImmIndirectU32:
		return mutator.StoreImmIndirectU32(i.Reg[0], i.Imm[0], i.Imm[1])
	case StoreIndirectU8:
		return mutator.StoreIndirectU8(i.Reg[0], i.Reg[1], i.Imm[0])
	case StoreIndirectU16:
		return mutator.StoreIndirectU16(i.Reg[0], i.Reg[1], i.Imm[0])
	case StoreIndirectU32:
		return mutator.StoreIndirectU32(i.Reg[0], i.Reg[1], i.Imm[0])
	case LoadIndirectU8:
		return mutator.LoadIndirectU8(i.Reg[0], i.Reg[1], i.Imm[0])
	case LoadIndirectI8:
		return mutator.LoadIndirectI8(i.Reg[0], i.Reg[1], i.Imm[0])
	case LoadIndirectU16:
		return mutator.LoadIndirectU16(i.Reg[0], i.Reg[1], i.Imm[0])
	case LoadIndirectI16:
		return mutator.LoadIndirectI16(i.Reg[0], i.Reg[1], i.Imm[0])
	case LoadIndirectU32:
		return mutator.LoadIndirectU32(i.Reg[0], i.Reg[1], i.Imm[0])
	case AddImm:
		mutator.AddImm(i.Reg[0], i.Reg[1], i.Imm[0])
	case AndImm:
		mutator.AndImm(i.Reg[0], i.Reg[1], i.Imm[0])
	case XorImm:
		mutator.XorImm(i.Reg[0], i.Reg[1], i.Imm[0])
	case OrImm:
		mutator.OrImm(i.Reg[0], i.Reg[1], i.Imm[0])
	case MulImm:
		mutator.MulImm(i.Reg[0], i.Reg[1], i.Imm[0])
	case MulUpperSignedSignedImm:
		mutator.MulUpperSignedSignedImm(i.Reg[0], i.Reg[1], i.Imm[0])
	case MulUpperUnsignedUnsignedImm:
		mutator.MulUpperUnsignedUnsignedImm(i.Reg[0], i.Reg[1], i.Imm[0])
	case SetLessThanUnsignedImm:
		mutator.SetLessThanUnsignedImm(i.Reg[0], i.Reg[1], i.Imm[0])
	case SetLessThanSignedImm:
		mutator.SetLessThanSignedImm(i.Reg[0], i.Reg[1], i.Imm[0])
	case ShiftLogicalLeftImm:
		mutator.ShiftLogicalLeftImm(i.Reg[0], i.Reg[1], i.Imm[0])
	case ShiftLogicalRightImm:
		mutator.ShiftLogicalRightImm(i.Reg[0], i.Reg[1], i.Imm[0])
	case ShiftArithmeticRightImm:
		mutator.ShiftArithmeticRightImm(i.Reg[0], i.Reg[1], i.Imm[0])
	case NegateAndAddImm:
		mutator.NegateAndAddImm(i.Reg[0], i.Reg[1], i.Imm[0])
	case SetGreaterThanUnsignedImm:
		mutator.SetGreaterThanUnsignedImm(i.Reg[0], i.Reg[1], i.Imm[0])
	case SetGreaterThanSignedImm:
		mutator.SetGreaterThanSignedImm(i.Reg[0], i.Reg[1], i.Imm[0])
	case ShiftLogicalRightImmAlt:
		mutator.ShiftLogicalRightImmAlt(i.Reg[0], i.Reg[1], i.Imm[0])
	case ShiftArithmeticRightImmAlt:
		mutator.ShiftArithmeticRightImmAlt(i.Reg[0], i.Reg[1], i.Imm[0])
	case ShiftLogicalLeftImmAlt:
		mutator.ShiftLogicalLeftImmAlt(i.Reg[0], i.Reg[1], i.Imm[0])
	case CmovIfZeroImm:
		mutator.CmovIfZeroImm(i.Reg[0], i.Reg[1], i.Imm[0])
	case CmovIfNotZeroImm:
		mutator.CmovIfNotZeroImm(i.Reg[0], i.Reg[1], i.Imm[0])
	case BranchEq:
		mutator.BranchEq(i.Reg[0], i.Reg[1], i.Imm[0])
	case BranchNotEq:
		mutator.BranchNotEq(i.Reg[0], i.Reg[1], i.Imm[0])
	case BranchLessUnsigned:
		mutator.BranchLessUnsigned(i.Reg[0], i.Reg[1], i.Imm[0])
	case BranchLessSigned:
		mutator.BranchLessSigned(i.Reg[0], i.Reg[1], i.Imm[0])
	case BranchGreaterOrEqualUnsigned:
		mutator.BranchGreaterOrEqualUnsigned(i.Reg[0], i.Reg[1], i.Imm[0])
	case BranchGreaterOrEqualSigned:
		mutator.BranchGreaterOrEqualSigned(i.Reg[0], i.Reg[1], i.Imm[0])
	case Add:
		mutator.Add(i.Reg[0], i.Reg[1], i.Reg[2])
	case Sub:
		mutator.Sub(i.Reg[0], i.Reg[1], i.Reg[2])
	case And:
		mutator.And(i.Reg[0], i.Reg[1], i.Reg[2])
	case Xor:
		mutator.Xor(i.Reg[0], i.Reg[1], i.Reg[2])
	case Or:
		mutator.Or(i.Reg[0], i.Reg[1], i.Reg[2])
	case Mul:
		mutator.Mul(i.Reg[0], i.Reg[1], i.Reg[2])
	case MulUpperSignedSigned:
		mutator.MulUpperSignedSigned(i.Reg[0], i.Reg[1], i.Reg[2])
	case MulUpperUnsignedUnsigned:
		mutator.MulUpperUnsignedUnsigned(i.Reg[0], i.Reg[1], i.Reg[2])
	case MulUpperSignedUnsigned:
		mutator.MulUpperSignedUnsigned(i.Reg[0], i.Reg[1], i.Reg[2])
	case SetLessThanUnsigned:
		mutator.SetLessThanUnsigned(i.Reg[0], i.Reg[1], i.Reg[2])
	case SetLessThanSigned:
		mutator.SetLessThanSigned(i.Reg[0], i.Reg[1], i.Reg[2])
	case ShiftLogicalLeft:
		mutator.ShiftLogicalLeft(i.Reg[0], i.Reg[1], i.Reg[2])
	case ShiftLogicalRight:
		mutator.ShiftLogicalRight(i.Reg[0], i.Reg[1], i.Reg[2])
	case ShiftArithmeticRight:
		mutator.ShiftArithmeticRight(i.Reg[0], i.Reg[1], i.Reg[2])
	case DivUnsigned:
		mutator.DivUnsigned(i.Reg[0], i.Reg[1], i.Reg[2])
	case DivSigned:
		mutator.DivSigned(i.Reg[0], i.Reg[1], i.Reg[2])
	case RemUnsigned:
		mutator.RemUnsigned(i.Reg[0], i.Reg[1], i.Reg[2])
	case RemSigned:
		mutator.RemSigned(i.Reg[0], i.Reg[1], i.Reg[2])
	case CmovIfZero:
		mutator.CmovIfZero(i.Reg[0], i.Reg[1], i.Reg[2])
	case CmovIfNotZero:
		mutator.CmovIfNotZero(i.Reg[0], i.Reg[1], i.Reg[2])
	case Jump:
		mutator.Jump(i.Imm[0])
	case Ecalli:
		if result := mutator.Ecalli(i.Imm[0]); result.Code != HostCallResultOk {
			return fmt.Errorf("host call terminated with code: %d - %s", result.Code, result.Code.String())
		} else if result.InnerCode != HostCallInnerCodeHalt {
			return fmt.Errorf("host call terminated with inner code: %d message: %s", result.InnerCode, result.Msg)
		}
	case StoreImmU8:
		return mutator.StoreImmU8(i.Imm[0], i.Imm[1])
	case StoreImmU16:
		return mutator.StoreImmU16(i.Imm[0], i.Imm[1])
	case StoreImmU32:
		return mutator.StoreImmU32(i.Imm[0], i.Imm[1])
	case MoveReg:
		mutator.MoveReg(i.Reg[0], i.Reg[1])
	case Sbrk:
		mutator.Sbrk(i.Reg[0], i.Reg[1])
	case LoadImmAndJumpIndirect:
		return mutator.LoadImmAndJumpIndirect(i.Reg[0], i.Reg[1], i.Imm[0], i.Imm[1])
	}
	return nil
}

func (i *Instruction) IsBasicBlockTermination() bool {
	switch i.Opcode {
	case Trap, Fallthrough, Jump, JumpIndirect, LoadImmAndJump,
		LoadImmAndJumpIndirect, BranchEq, BranchEqImm,
		BranchGreaterOrEqualSigned, BranchGreaterOrEqualSignedImm,
		BranchGreaterOrEqualUnsigned, BranchGreaterOrEqualUnsignedImm,
		BranchGreaterSignedImm, BranchGreaterUnsignedImm, BranchLessOrEqualSignedImm,
		BranchLessOrEqualUnsignedImm, BranchLessSigned, BranchLessSignedImm,
		BranchLessUnsigned, BranchLessUnsignedImm, BranchNotEq, BranchNotEqImm:
		return true
	}
	return false
}
