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
