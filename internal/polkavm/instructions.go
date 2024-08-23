package polkavm

import (
	"encoding/binary"
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
	instrNone = []InstructionCode{Trap, Fallthrough}
	// Instructions with args: reg, imm
	instrRegImm = []InstructionCode{JumpIndirect, LoadImm, LoadU8, LoadI8, LoadU16, LoadI16, LoadU32, StoreU8, StoreU16, StoreU32}
	// Instructions with args: reg, imm, offset
	instrRegImmOffset = []InstructionCode{LoadImmAndJump, BranchEqImm, BranchNotEqImm, BranchLessUnsignedImm, BranchLessSignedImm, BranchGreaterOrEqualUnsignedImm, BranchGreaterOrEqualSignedImm, BranchLessOrEqualSignedImm, BranchLessOrEqualUnsignedImm, BranchGreaterSignedImm, BranchGreaterUnsignedImm}
	// Instructions with args: reg, imm, imm
	instrRegImm2 = []InstructionCode{StoreImmIndirectU8, StoreImmIndirectU16, StoreImmIndirectU32}
	// Instructions with args: reg, reg, imm
	instrReg2Imm = []InstructionCode{StoreIndirectU8, StoreIndirectU16, StoreIndirectU32, LoadIndirectU8, LoadIndirectI8, LoadIndirectU16, LoadIndirectI16, LoadIndirectU32, AddImm, AndImm, XorImm, OrImm, MulImm, MulUpperSignedSignedImm, MulUpperUnsignedUnsignedImm, SetLessThanUnsignedImm, SetLessThanSignedImm, ShiftLogicalLeftImm, ShiftLogicalRightImm, ShiftArithmeticRightImm, NegateAndAddImm, SetGreaterThanUnsignedImm, SetGreaterThanSignedImm, ShiftLogicalRightImmAlt, ShiftArithmeticRightImmAlt, ShiftLogicalLeftImmAlt, CmovIfZeroImm, CmovIfNotZeroImm}
	// Instructions with args: reg, reg, offset
	instrReg2Offset = []InstructionCode{BranchEq, BranchNotEq, BranchLessUnsigned, BranchLessSigned, BranchGreaterOrEqualUnsigned, BranchGreaterOrEqualSigned}
	// Instructions with args: reg, reg, reg
	instrReg3 = []InstructionCode{Add, Sub, And, Xor, Or, Mul, MulUpperSignedSigned, MulUpperUnsignedUnsigned, MulUpperSignedUnsigned, SetLessThanUnsigned, SetLessThanSigned, ShiftLogicalLeft, ShiftLogicalRight, ShiftArithmeticRight, DivUnsigned, DivSigned, RemUnsigned, RemSigned, CmovIfZero, CmovIfNotZero}
	// Instructions with args: offset
	instrOffset = []InstructionCode{Jump}
	// Instructions with args: imm
	instrImm = []InstructionCode{Ecalli}
	// Instructions with args: imm, imm
	instrImm2 = []InstructionCode{StoreImmU8, StoreImmU16, StoreImmU32}
	// Instructions with args: reg, reg
	instrRegReg = []InstructionCode{MoveReg, Sbrk}
	// Instructions with args: reg, reg, imm, imm
	instrReg2Imm2 = []InstructionCode{LoadImmAndJumpIndirect}
)

type InstrParseArgFunc func(chunk []byte, instructionOffset, argsLength uint32) ([]Reg, []uint32)

var parseArgsTable = map[InstructionCode]InstrParseArgFunc{}

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
