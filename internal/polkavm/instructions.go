package polkavm

type Opcode byte

// GasCosts delta gas for each operation (ϱ∆)
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
	LoadImm64:                       1,
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

type InstructionType byte

var InstructionForType = map[Opcode]InstructionType{}

const (
	InstrNone = iota
	InstrImm
	InstrRegImmExt
	InstrImm2
	InstrOffset
	InstrRegImm
	InstrRegImm2
	InstrRegImmOffset
	InstrRegReg
	InstrReg2Imm
	InstrReg2Offset
	InstrReg2Imm2
	InstrReg3
)

func init() {
	for _, code := range instrNone {
		InstructionForType[code] = InstrNone
	}
	for _, code := range instrRegImm {
		InstructionForType[code] = InstrRegImm
	}
	for _, code := range instrRegImmOffset {
		InstructionForType[code] = InstrRegImmOffset
	}
	for _, code := range instrRegImm2 {
		InstructionForType[code] = InstrRegImm2
	}
	for _, code := range instrReg2Imm {
		InstructionForType[code] = InstrReg2Imm
	}
	for _, code := range instrReg2Offset {
		InstructionForType[code] = InstrReg2Offset
	}
	for _, code := range instrReg3 {
		InstructionForType[code] = InstrReg3
	}
	for _, code := range instrOffset {
		InstructionForType[code] = InstrOffset
	}
	for _, code := range instrImm {
		InstructionForType[code] = InstrImm
	}
	for _, code := range instrImm2 {
		InstructionForType[code] = InstrImm2
	}
	for _, code := range instrRegReg {
		InstructionForType[code] = InstrRegReg
	}
	for _, code := range instrReg2Imm2 {
		InstructionForType[code] = InstrReg2Imm2
	}
	for _, code := range instrRegImmExt {
		InstructionForType[code] = InstrRegImmExt
	}
}

// IsBasicBlockTermination (eq A.3)
func (o Opcode) IsBasicBlockTermination() bool {
	switch o {
	case
		// Trap and fallthrough: trap, fallthrough
		Trap, Fallthrough,

		// Jumps: jump, jump_ind
		Jump, JumpIndirect,

		// Load-and-Jumps: load_imm_jump , load_imm_jump_ind
		LoadImmAndJump, LoadImmAndJumpIndirect,

		// Branches: branch_eq, branch_ne, branch_ge_u, branch_ge_s, branch_lt_u, branch_lt_s, branch_eq_imm, branch_ne_imm
		BranchEq, BranchNotEq, BranchGreaterOrEqualUnsigned, BranchGreaterOrEqualSigned,
		BranchLessUnsigned, BranchLessSigned, BranchEqImm, BranchNotEqImm,

		// Immediate branches: branch_lt_u_imm, branch_lt_s_imm, branch_le_u_imm, branch_le_s_imm, branch_ge_u_imm, branch_ge_s_imm, branch_gt_u_imm, branch_gt_s_imm
		BranchLessUnsignedImm, BranchLessSignedImm, BranchLessOrEqualUnsignedImm, BranchLessOrEqualSignedImm,
		BranchGreaterOrEqualUnsignedImm, BranchGreaterOrEqualSignedImm, BranchGreaterUnsignedImm, BranchGreaterSignedImm:
		return true
	}
	return false
}
