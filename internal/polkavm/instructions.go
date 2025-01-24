package polkavm

import (
	"fmt"
	"github.com/eigerco/strawberry/pkg/serialization/codec/jam"
)

type Opcode byte

var GasCosts = map[Opcode]Gas{
	Trap:                            1,
	Fallthrough:                     1,
	Ecalli:                          1,
	StoreImmU8:                      1,
	StoreImmU16:                     1,
	StoreImmU32:                     1,
	StoreImmU64:                     1,
	Jump:                            1,
	JumpIndirect:                    1,
	LoadImm:                         1,
	LoadU8:                          1,
	LoadI8:                          1,
	LoadU16:                         1,
	LoadI16:                         1,
	LoadU32:                         1,
	LoadI32:                         1,
	LoadU64:                         1,
	StoreU8:                         1,
	StoreU16:                        1,
	StoreU32:                        1,
	StoreU64:                        1,
	StoreImmIndirectU8:              1,
	StoreImmIndirectU16:             1,
	StoreImmIndirectU32:             1,
	StoreImmIndirectU64:             1,
	LoadImmAndJump:                  1,
	BranchEqImm:                     1,
	BranchNotEqImm:                  1,
	BranchLessUnsignedImm:           1,
	BranchLessOrEqualUnsignedImm:    1,
	BranchGreaterOrEqualUnsignedImm: 1,
	BranchGreaterUnsignedImm:        1,
	BranchLessSignedImm:             1,
	BranchLessOrEqualSignedImm:      1,
	BranchGreaterOrEqualSignedImm:   1,
	BranchGreaterSignedImm:          1,
	MoveReg:                         1,
	Sbrk:                            1,
	CountSetBits64:                  1,
	CountSetBits32:                  1,
	LeadingZeroBits64:               1,
	LeadingZeroBits32:               1,
	TrailingZeroBits64:              1,
	TrailingZeroBits32:              1,
	SignExtend8:                     1,
	SignExtend16:                    1,
	ZeroExtend16:                    1,
	ReverseBytes:                    1,
	StoreIndirectU8:                 1,
	StoreIndirectU16:                1,
	StoreIndirectU32:                1,
	StoreIndirectU64:                1,
	LoadIndirectU8:                  1,
	LoadIndirectI8:                  1,
	LoadIndirectU16:                 1,
	LoadIndirectI16:                 1,
	LoadIndirectU32:                 1,
	LoadIndirectI32:                 1,
	LoadIndirectU64:                 1,
	AddImm32:                        1,
	AndImm:                          1,
	XorImm:                          1,
	OrImm:                           1,
	MulImm32:                        1,
	SetLessThanUnsignedImm:          1,
	SetLessThanSignedImm:            1,
	ShiftLogicalLeftImm32:           1,
	ShiftLogicalRightImm32:          1,
	ShiftArithmeticRightImm32:       1,
	NegateAndAddImm32:               1,
	SetGreaterThanUnsignedImm:       1,
	SetGreaterThanSignedImm:         1,
	ShiftLogicalRightImmAlt32:       1,
	ShiftArithmeticRightImmAlt32:    1,
	ShiftLogicalLeftImmAlt32:        1,
	CmovIfZeroImm:                   1,
	CmovIfNotZeroImm:                1,
	AddImm64:                        1,
	MulImm64:                        1,
	ShiftLogicalLeftImm64:           1,
	ShiftLogicalRightImm64:          1,
	ShiftArithmeticRightImm64:       1,
	NegateAndAddImm64:               1,
	ShiftLogicalLeftImmAlt64:        1,
	ShiftLogicalRightImmAlt64:       1,
	ShiftArithmeticRightImmAlt64:    1,
	RotR64Imm:                       1,
	RotR64ImmAlt:                    1,
	RotR32Imm:                       1,
	RotR32ImmAlt:                    1,
	BranchEq:                        1,
	BranchNotEq:                     1,
	BranchLessUnsigned:              1,
	BranchLessSigned:                1,
	BranchGreaterOrEqualUnsigned:    1,
	BranchGreaterOrEqualSigned:      1,
	LoadImmAndJumpIndirect:          1,
	Add32:                           1,
	Sub32:                           1,
	Mul32:                           1,
	DivUnsigned32:                   1,
	DivSigned32:                     1,
	RemUnsigned32:                   1,
	RemSigned32:                     1,
	ShiftLogicalLeft32:              1,
	ShiftLogicalRight32:             1,
	ShiftArithmeticRight32:          1,
	Add64:                           1,
	Sub64:                           1,
	Mul64:                           1,
	DivUnsigned64:                   1,
	DivSigned64:                     1,
	RemUnsigned64:                   1,
	RemSigned64:                     1,
	ShiftLogicalLeft64:              1,
	ShiftLogicalRight64:             1,
	ShiftArithmeticRight64:          1,
	And:                             1,
	Xor:                             1,
	Or:                              1,
	MulUpperSignedSigned:            1,
	MulUpperUnsignedUnsigned:        1,
	MulUpperSignedUnsigned:          1,
	SetLessThanUnsigned:             1,
	SetLessThanSigned:               1,
	CmovIfZero:                      1,
	CmovIfNotZero:                   1,
	RotL64:                          1,
	RotL32:                          1,
	RotR64:                          1,
	RotR32:                          1,
	AndInv:                          1,
	OrInv:                           1,
	Xnor:                            1,
	Max:                             1,
	MaxU:                            1,
	Min:                             1,
	MinU:                            1,
}

type Reg uint

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
		return "UNKNOWN"
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

var (
	// Instructions without Arguments
	instrNone = []Opcode{Trap, Fallthrough}
	// Instructions with Arguments of One Immediate.
	instrImm = []Opcode{Ecalli}
	// Instructions with Arguments of One Register and One Extended Width Immediate.
	instrRegImmExt = []Opcode{LoadImm64}
	// Instructions with Arguments of Two Immediates.
	instrImm2 = []Opcode{StoreImmU8, StoreImmU16, StoreImmU32, StoreImmU64}
	// Instructions with Arguments of One Offset.
	instrOffset = []Opcode{Jump}
	// Instructions with Arguments of One Register & One Immediate.
	instrRegImm = []Opcode{
		JumpIndirect, LoadImm, LoadU8, LoadI8, LoadU16, LoadI16, LoadU32, LoadI32, LoadU64,
		StoreU8, StoreU16, StoreU32, StoreU64,
	}
	// Instructions with Arguments of One Register & Two Immediates.
	instrRegImm2 = []Opcode{StoreImmIndirectU8, StoreImmIndirectU16, StoreImmIndirectU32, StoreImmIndirectU64}
	// Instructions with Arguments of One Register, One Immediate and One Offset.
	instrRegImmOffset = []Opcode{
		LoadImmAndJump, BranchEqImm, BranchNotEqImm, BranchLessUnsignedImm, BranchLessOrEqualUnsignedImm,
		BranchGreaterOrEqualUnsignedImm, BranchGreaterUnsignedImm, BranchLessSignedImm,
		BranchLessOrEqualSignedImm, BranchGreaterOrEqualSignedImm, BranchGreaterSignedImm,
	}
	// Instructions with Arguments of Two Registers.
	instrRegReg = []Opcode{
		MoveReg, Sbrk,
		CountSetBits64, CountSetBits32, LeadingZeroBits64,
		LeadingZeroBits32, TrailingZeroBits64, TrailingZeroBits32,
		SignExtend8, SignExtend16, ZeroExtend16, ReverseBytes,
	}
	// Instructions with Arguments of Two Registers & One Immediate.
	instrReg2Imm = []Opcode{
		StoreIndirectU8, StoreIndirectU16, StoreIndirectU32, StoreIndirectU64,
		LoadIndirectU8, LoadIndirectI8, LoadIndirectU16, LoadIndirectI16,
		LoadIndirectU32, LoadIndirectI32, LoadIndirectU64,
		AddImm32, AndImm, XorImm, OrImm, MulImm32,
		SetLessThanUnsignedImm, SetLessThanSignedImm,
		ShiftLogicalLeftImm32, ShiftLogicalRightImm32, ShiftArithmeticRightImm32,
		NegateAndAddImm32, SetGreaterThanUnsignedImm, SetGreaterThanSignedImm,
		ShiftLogicalRightImmAlt32, ShiftArithmeticRightImmAlt32, ShiftLogicalLeftImmAlt32,
		CmovIfZeroImm, CmovIfNotZeroImm,
		AddImm64, MulImm64,
		ShiftLogicalLeftImm64, ShiftLogicalRightImm64, ShiftArithmeticRightImm64,
		NegateAndAddImm64,
		ShiftLogicalLeftImmAlt64, ShiftLogicalRightImmAlt64, ShiftArithmeticRightImmAlt64,
		RotR64Imm, RotR64ImmAlt, RotR32Imm, RotR32ImmAlt,
	}
	// Instructions with Arguments of Two Registers & One Offset.
	instrReg2Offset = []Opcode{
		BranchEq, BranchNotEq, BranchLessUnsigned, BranchLessSigned,
		BranchGreaterOrEqualUnsigned, BranchGreaterOrEqualSigned,
	}
	// Instruction with Arguments of Two Registers and Two Immediates.
	instrReg2Imm2 = []Opcode{LoadImmAndJumpIndirect}
	// Instructions with Arguments of Three Registers.
	instrReg3 = []Opcode{
		Add32, Sub32, Mul32, DivUnsigned32, DivSigned32, RemUnsigned32, RemSigned32,
		ShiftLogicalLeft32, ShiftLogicalRight32, ShiftArithmeticRight32,
		Add64, Sub64, Mul64, DivUnsigned64, DivSigned64, RemUnsigned64, RemSigned64,
		ShiftLogicalLeft64, ShiftLogicalRight64, ShiftArithmeticRight64,
		And, Xor, Or, MulUpperSignedSigned, MulUpperUnsignedUnsigned, MulUpperSignedUnsigned,
		SetLessThanUnsigned, SetLessThanSigned, CmovIfZero, CmovIfNotZero,
		RotL64, RotL32, RotR64, RotR32, AndInv, OrInv, Xnor, Max, MaxU, Min, MinU,
	}
)

type InstrParseArgFunc func(chunk []byte, instructionOffset, argsLength uint32) ([]Reg, []uint32, error)

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
func read(slice []byte, offset, length uint32) (uint32, error) {
	slice = slice[offset : offset+length]
	if length == 0 {
		return 0, nil
	}
	imm := uint32(0)
	if err := jam.Unmarshal(slice, &imm); err != nil {
		return 0, fmt.Errorf("unexpected err %w", err)
	}
	return imm, nil
}

func parseArgsImm(code []byte, _, skip uint32) ([]Reg, []uint32, error) {
	immLength := min(4, skip)
	imm, err := read(code, 0, immLength)
	if err != nil {
		return nil, nil, err
	}

	return nil, []uint32{sext(imm, immLength)}, nil
}

func parseArgsImmOffset(code []byte, instructionOffset, skip uint32) ([]Reg, []uint32, error) {
	_, imm, err := parseArgsImm(code, instructionOffset, skip)
	if err != nil {
		return nil, nil, err
	}
	return nil, []uint32{instructionOffset + imm[0]}, nil
}

func parseArgsImm2(code []byte, _, skip uint32) ([]Reg, []uint32, error) {
	imm1Length := min(4, uint32(code[0])&0b111)
	imm2Length := clamp(0, 4, skip-imm1Length-1)
	imm1, err := read(code, 1, imm1Length)
	if err != nil {
		return nil, nil, err
	}
	imm1 = sext(imm1, imm1Length)
	imm2, err := read(code, 1+imm1Length, imm2Length)
	if err != nil {
		return nil, nil, err
	}
	imm2 = sext(imm2, imm2Length)
	return nil, []uint32{imm1, imm2}, nil
}

func parseArgsNone(_ []byte, _, _ uint32) ([]Reg, []uint32, error) {
	return nil, nil, nil
}

func parseArgsRegImm(code []byte, _, skip uint32) ([]Reg, []uint32, error) {
	reg := min(12, code[0]&0b1111)
	immLength := clamp(0, 4, skip-1)
	imm, err := read(code, 1, immLength)
	if err != nil {
		return nil, nil, err
	}
	imm = sext(imm, immLength)
	return []Reg{Reg(reg)}, []uint32{imm}, nil
}

func parseArgsRegImmOffset(code []byte, instructionOffset, skip uint32) ([]Reg, []uint32, error) {
	regs, imm, err := parseArgsRegImm2(code, instructionOffset, skip)
	if err != nil {
		return nil, nil, err
	}
	return regs, []uint32{imm[0], instructionOffset + imm[1]}, nil
}

func parseArgsRegImm2(code []byte, _, skip uint32) ([]Reg, []uint32, error) {
	reg := min(12, code[0]&0b1111)
	imm1Length := min(4, uint32(code[0]>>4)&0b111)
	imm2Length := clamp(0, 4, skip-imm1Length-1)
	imm1, err := read(code, 1, imm1Length)
	if err != nil {
		return nil, nil, err
	}
	imm1 = sext(imm1, imm1Length)
	imm2, err := read(code, 1+imm1Length, imm2Length)
	if err != nil {
		return nil, nil, err
	}
	imm2 = sext(imm2, imm2Length)
	return []Reg{Reg(reg)}, []uint32{imm1, imm2}, nil
}

func parseArgsRegs2Imm2(code []byte, _, skip uint32) ([]Reg, []uint32, error) {
	reg1 := min(12, code[0]&0b1111)
	reg2 := min(12, code[0]>>4)
	imm1Length := min(4, uint32(code[1])&0b111)
	imm2Length := clamp(0, 4, skip-imm1Length-2)
	imm1, err := read(code, 2, imm1Length)
	if err != nil {
		return nil, nil, err
	}
	imm1 = sext(imm1, imm1Length)
	imm2, err := read(code, 2+imm1Length, imm2Length)
	if err != nil {
		return nil, nil, err
	}
	imm2 = sext(imm2, imm2Length)
	return []Reg{Reg(reg1), Reg(reg2)}, []uint32{imm1, imm2}, nil
}

func parseArgsRegs2Imm(code []byte, _, skip uint32) ([]Reg, []uint32, error) {
	immLength := clamp(0, 4, uint32(skip)-1)
	imm, err := read(code, 1, immLength)
	if err != nil {
		return nil, nil, err
	}
	imm = sext(imm, immLength)
	return []Reg{
		Reg(min(12, code[0]&0b1111)),
		Reg(min(12, code[0]>>4)),
	}, []uint32{imm}, nil
}

func parseArgsRegs3(code []byte, _, _ uint32) ([]Reg, []uint32, error) {
	return []Reg{
		Reg(min(12, code[1]&0b1111)),
		Reg(min(12, code[0]&0b1111)),
		Reg(min(12, code[0]>>4)),
	}, nil, nil
}

func parseArgsRegs2(code []byte, _, _ uint32) ([]Reg, []uint32, error) {
	return []Reg{Reg(min(12, code[0]&0b1111)), Reg(min(12, code[0]>>4))}, nil, nil
}

func parseArgsRegs2Offset(code []byte, instructionOffset, skip uint32) ([]Reg, []uint32, error) {
	regs, imm, err := parseArgsRegs2Imm(code, instructionOffset, skip)
	if err != nil {
		return nil, nil, err
	}
	return regs, []uint32{instructionOffset + imm[0]}, nil
}

type Instruction struct {
	Opcode Opcode
	Imm    []uint32
	ExtImm uint64
	Reg    []Reg
	Offset uint32
	Length uint32
}

func (i *Instruction) Mutate(mutator Mutator) (uint32, error) {
	switch i.Opcode {
	case Trap:
		return 0, mutator.Trap()
	case Fallthrough:
		mutator.Fallthrough()
	case JumpIndirect:
		return 0, mutator.JumpIndirect(i.Reg[0], i.Imm[0])
	case LoadImm:
		mutator.LoadImm(i.Reg[0], i.Imm[0])
	case LoadU8:
		return 0, mutator.LoadU8(i.Reg[0], i.Imm[0])
	case LoadI8:
		return 0, mutator.LoadI8(i.Reg[0], i.Imm[0])
	case LoadU16:
		return 0, mutator.LoadU16(i.Reg[0], i.Imm[0])
	case LoadI16:
		return 0, mutator.LoadI16(i.Reg[0], i.Imm[0])
	case LoadU32:
		return 0, mutator.LoadU32(i.Reg[0], i.Imm[0])
	case LoadI32:
		return 0, mutator.LoadI32(i.Reg[0], i.Imm[0])
	case LoadU64:
		return 0, mutator.LoadU64(i.Reg[0], i.Imm[0])
	case StoreU8:
		return 0, mutator.StoreU8(i.Reg[0], i.Imm[0])
	case StoreU16:
		return 0, mutator.StoreU16(i.Reg[0], i.Imm[0])
	case StoreU32:
		return 0, mutator.StoreU32(i.Reg[0], i.Imm[0])
	case StoreU64:
		return 0, mutator.StoreU64(i.Reg[0], i.Imm[0])
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
		return 0, mutator.StoreImmIndirectU8(i.Reg[0], i.Imm[0], i.Imm[1])
	case StoreImmIndirectU16:
		return 0, mutator.StoreImmIndirectU16(i.Reg[0], i.Imm[0], i.Imm[1])
	case StoreImmIndirectU32:
		return 0, mutator.StoreImmIndirectU32(i.Reg[0], i.Imm[0], i.Imm[1])
	case StoreImmIndirectU64:
		return 0, mutator.StoreImmIndirectU64(i.Reg[0], i.Imm[0], i.Imm[1])
	case StoreIndirectU8:
		return 0, mutator.StoreIndirectU8(i.Reg[0], i.Reg[1], i.Imm[0])
	case StoreIndirectU16:
		return 0, mutator.StoreIndirectU16(i.Reg[0], i.Reg[1], i.Imm[0])
	case StoreIndirectU32:
		return 0, mutator.StoreIndirectU32(i.Reg[0], i.Reg[1], i.Imm[0])
	case StoreIndirectU64:
		return 0, mutator.StoreIndirectU64(i.Reg[0], i.Reg[1], i.Imm[0])
	case LoadIndirectU8:
		return 0, mutator.LoadIndirectU8(i.Reg[0], i.Reg[1], i.Imm[0])
	case LoadIndirectI8:
		return 0, mutator.LoadIndirectI8(i.Reg[0], i.Reg[1], i.Imm[0])
	case LoadIndirectU16:
		return 0, mutator.LoadIndirectU16(i.Reg[0], i.Reg[1], i.Imm[0])
	case LoadIndirectI16:
		return 0, mutator.LoadIndirectI16(i.Reg[0], i.Reg[1], i.Imm[0])
	case LoadIndirectU32:
		return 0, mutator.LoadIndirectU32(i.Reg[0], i.Reg[1], i.Imm[0])
	case LoadIndirectI32:
		return 0, mutator.LoadIndirectI32(i.Reg[0], i.Reg[1], i.Imm[0])
	case LoadIndirectU64:
		return 0, mutator.LoadIndirectU64(i.Reg[0], i.Reg[1], i.Imm[0])
	case AddImm32:
		mutator.AddImm32(i.Reg[0], i.Reg[1], i.Imm[0])
	case AddImm64:
		mutator.AddImm64(i.Reg[0], i.Reg[1], i.Imm[0])
	case AndImm:
		mutator.AndImm(i.Reg[0], i.Reg[1], i.Imm[0])
	case XorImm:
		mutator.XorImm(i.Reg[0], i.Reg[1], i.Imm[0])
	case OrImm:
		mutator.OrImm(i.Reg[0], i.Reg[1], i.Imm[0])
	case MulImm32:
		mutator.MulImm32(i.Reg[0], i.Reg[1], i.Imm[0])
	case MulImm64:
		mutator.MulImm64(i.Reg[0], i.Reg[1], i.Imm[0])
	case SetLessThanUnsignedImm:
		mutator.SetLessThanUnsignedImm(i.Reg[0], i.Reg[1], i.Imm[0])
	case SetLessThanSignedImm:
		mutator.SetLessThanSignedImm(i.Reg[0], i.Reg[1], i.Imm[0])
	case ShiftLogicalLeftImm32:
		mutator.ShiftLogicalLeftImm32(i.Reg[0], i.Reg[1], i.Imm[0])
	case ShiftLogicalLeftImm64:
		mutator.ShiftLogicalLeftImm64(i.Reg[0], i.Reg[1], i.Imm[0])
	case ShiftLogicalRightImm32:
		mutator.ShiftLogicalRightImm32(i.Reg[0], i.Reg[1], i.Imm[0])
	case ShiftLogicalRightImm64:
		mutator.ShiftLogicalRightImm64(i.Reg[0], i.Reg[1], i.Imm[0])
	case ShiftArithmeticRightImm32:
		mutator.ShiftArithmeticRightImm32(i.Reg[0], i.Reg[1], i.Imm[0])
	case ShiftArithmeticRightImm64:
		mutator.ShiftArithmeticRightImm64(i.Reg[0], i.Reg[1], i.Imm[0])
	case NegateAndAddImm32:
		mutator.NegateAndAddImm32(i.Reg[0], i.Reg[1], i.Imm[0])
	case NegateAndAddImm64:
		mutator.NegateAndAddImm64(i.Reg[0], i.Reg[1], i.Imm[0])
	case SetGreaterThanUnsignedImm:
		mutator.SetGreaterThanUnsignedImm(i.Reg[0], i.Reg[1], i.Imm[0])
	case SetGreaterThanSignedImm:
		mutator.SetGreaterThanSignedImm(i.Reg[0], i.Reg[1], i.Imm[0])
	case ShiftLogicalRightImmAlt32:
		mutator.ShiftLogicalRightImmAlt32(i.Reg[0], i.Reg[1], i.Imm[0])
	case ShiftLogicalRightImmAlt64:
		mutator.ShiftLogicalRightImmAlt64(i.Reg[0], i.Reg[1], i.Imm[0])
	case ShiftArithmeticRightImmAlt32:
		mutator.ShiftArithmeticRightImmAlt32(i.Reg[0], i.Reg[1], i.Imm[0])
	case ShiftArithmeticRightImmAlt64:
		mutator.ShiftArithmeticRightImmAlt64(i.Reg[0], i.Reg[1], i.Imm[0])
	case ShiftLogicalLeftImmAlt32:
		mutator.ShiftLogicalLeftImmAlt32(i.Reg[0], i.Reg[1], i.Imm[0])
	case ShiftLogicalLeftImmAlt64:
		mutator.ShiftLogicalLeftImmAlt64(i.Reg[0], i.Reg[1], i.Imm[0])
	case CmovIfZeroImm:
		mutator.CmovIfZeroImm(i.Reg[0], i.Reg[1], i.Imm[0])
	case CmovIfNotZeroImm:
		mutator.CmovIfNotZeroImm(i.Reg[0], i.Reg[1], i.Imm[0])
	case RotR64Imm:
		mutator.RotateRight64Imm(i.Reg[0], i.Reg[1], i.Imm[0])
	case RotR64ImmAlt:
		mutator.RotateRight64ImmAlt(i.Reg[0], i.Reg[1], i.Imm[0])
	case RotR32Imm:
		mutator.RotateRight32Imm(i.Reg[0], i.Reg[1], i.Imm[0])
	case RotR32ImmAlt:
		mutator.RotateRight32ImmAlt(i.Reg[0], i.Reg[1], i.Imm[0])
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
	case Add32:
		mutator.Add32(i.Reg[0], i.Reg[1], i.Reg[2])
	case Add64:
		mutator.Add64(i.Reg[0], i.Reg[1], i.Reg[2])
	case Sub32:
		mutator.Sub32(i.Reg[0], i.Reg[1], i.Reg[2])
	case Sub64:
		mutator.Sub64(i.Reg[0], i.Reg[1], i.Reg[2])
	case And:
		mutator.And(i.Reg[0], i.Reg[1], i.Reg[2])
	case Xor:
		mutator.Xor(i.Reg[0], i.Reg[1], i.Reg[2])
	case Or:
		mutator.Or(i.Reg[0], i.Reg[1], i.Reg[2])
	case Mul32:
		mutator.Mul32(i.Reg[0], i.Reg[1], i.Reg[2])
	case Mul64:
		mutator.Mul64(i.Reg[0], i.Reg[1], i.Reg[2])
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
	case ShiftLogicalLeft32:
		mutator.ShiftLogicalLeft32(i.Reg[0], i.Reg[1], i.Reg[2])
	case ShiftLogicalLeft64:
		mutator.ShiftLogicalLeft64(i.Reg[0], i.Reg[1], i.Reg[2])
	case ShiftLogicalRight32:
		mutator.ShiftLogicalRight32(i.Reg[0], i.Reg[1], i.Reg[2])
	case ShiftLogicalRight64:
		mutator.ShiftLogicalRight64(i.Reg[0], i.Reg[1], i.Reg[2])
	case ShiftArithmeticRight32:
		mutator.ShiftArithmeticRight32(i.Reg[0], i.Reg[1], i.Reg[2])
	case ShiftArithmeticRight64:
		mutator.ShiftArithmeticRight64(i.Reg[0], i.Reg[1], i.Reg[2])
	case DivUnsigned32:
		mutator.DivUnsigned32(i.Reg[0], i.Reg[1], i.Reg[2])
	case DivUnsigned64:
		mutator.DivUnsigned64(i.Reg[0], i.Reg[1], i.Reg[2])
	case DivSigned32:
		mutator.DivSigned32(i.Reg[0], i.Reg[1], i.Reg[2])
	case DivSigned64:
		mutator.DivSigned64(i.Reg[0], i.Reg[1], i.Reg[2])
	case RemUnsigned32:
		mutator.RemUnsigned32(i.Reg[0], i.Reg[1], i.Reg[2])
	case RemUnsigned64:
		mutator.RemUnsigned64(i.Reg[0], i.Reg[1], i.Reg[2])
	case RemSigned32:
		mutator.RemSigned32(i.Reg[0], i.Reg[1], i.Reg[2])
	case RemSigned64:
		mutator.RemSigned64(i.Reg[0], i.Reg[1], i.Reg[2])
	case CmovIfZero:
		mutator.CmovIfZero(i.Reg[0], i.Reg[1], i.Reg[2])
	case CmovIfNotZero:
		mutator.CmovIfNotZero(i.Reg[0], i.Reg[1], i.Reg[2])
	case RotL64:
		mutator.RotateLeft64(i.Reg[0], i.Reg[1], i.Reg[2])
	case RotL32:
		mutator.RotateLeft32(i.Reg[0], i.Reg[1], i.Reg[2])
	case RotR64:
		mutator.RotateRight64(i.Reg[0], i.Reg[1], i.Reg[2])
	case RotR32:
		mutator.RotateRight32(i.Reg[0], i.Reg[1], i.Reg[2])
	case AndInv:
		mutator.AndInverted(i.Reg[0], i.Reg[1], i.Reg[2])
	case OrInv:
		mutator.OrInverted(i.Reg[0], i.Reg[1], i.Reg[2])
	case Xnor:
		mutator.Xnor(i.Reg[0], i.Reg[1], i.Reg[2])
	case Max:
		mutator.Max(i.Reg[0], i.Reg[1], i.Reg[2])
	case MaxU:
		mutator.MaxUnsigned(i.Reg[0], i.Reg[1], i.Reg[2])
	case Min:
		mutator.Min(i.Reg[0], i.Reg[1], i.Reg[2])
	case MinU:
		mutator.MinUnsigned(i.Reg[0], i.Reg[1], i.Reg[2])
	case Jump:
		mutator.Jump(i.Imm[0])
	case Ecalli:
		return i.Imm[0], ErrHostCall
	case StoreImmU8:
		return 0, mutator.StoreImmU8(i.Imm[0], i.Imm[1])
	case StoreImmU16:
		return 0, mutator.StoreImmU16(i.Imm[0], i.Imm[1])
	case StoreImmU32:
		return 0, mutator.StoreImmU32(i.Imm[0], i.Imm[1])
	case StoreImmU64:
		return 0, mutator.StoreImmU64(i.Imm[0], i.Imm[1])
	case MoveReg:
		mutator.MoveReg(i.Reg[0], i.Reg[1])
	case Sbrk:
		return 0, mutator.Sbrk(i.Reg[0], i.Reg[1])
	case CountSetBits64:
		mutator.CountSetBits64(i.Reg[0], i.Reg[1])
	case CountSetBits32:
		mutator.CountSetBits32(i.Reg[0], i.Reg[1])
	case LeadingZeroBits64:
		mutator.LeadingZeroBits64(i.Reg[0], i.Reg[1])
	case LeadingZeroBits32:
		mutator.LeadingZeroBits32(i.Reg[0], i.Reg[1])
	case TrailingZeroBits64:
		mutator.TrailingZeroBits64(i.Reg[0], i.Reg[1])
	case TrailingZeroBits32:
		mutator.TrailingZeroBits32(i.Reg[0], i.Reg[1])
	case SignExtend8:
		mutator.SignExtend8(i.Reg[0], i.Reg[1])
	case SignExtend16:
		mutator.SignExtend16(i.Reg[0], i.Reg[1])
	case ZeroExtend16:
		mutator.ZeroExtend16(i.Reg[0], i.Reg[1])
	case ReverseBytes:
		mutator.ReverseBytes(i.Reg[0], i.Reg[1])
	case LoadImmAndJumpIndirect:
		return 0, mutator.LoadImmAndJumpIndirect(i.Reg[0], i.Reg[1], i.Imm[0], i.Imm[1])
	case LoadImm64:
		mutator.LoadImm64(i.Reg[0], i.ExtImm)
		return 0, nil
	default:
		return 0, fmt.Errorf("unsupported instruction opcode: %d", i.Opcode)
	}
	return 0, nil
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
