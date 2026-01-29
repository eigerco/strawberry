package pvm

type Opcode byte

// GasCosts delta gas for each operation (ϱ∆)
const (
	TrapCost                            Gas = 1
	FallthroughCost                     Gas = 1
	EcalliCost                          Gas = 1
	StoreImmU8Cost                      Gas = 1
	StoreImmU16Cost                     Gas = 1
	StoreImmU32Cost                     Gas = 1
	StoreImmU64Cost                     Gas = 1
	JumpCost                            Gas = 1
	JumpIndirectCost                    Gas = 1
	LoadImmCost                         Gas = 1
	LoadU8Cost                          Gas = 1
	LoadI8Cost                          Gas = 1
	LoadU16Cost                         Gas = 1
	LoadI16Cost                         Gas = 1
	LoadImm64Cost                       Gas = 1
	LoadU32Cost                         Gas = 1
	LoadI32Cost                         Gas = 1
	LoadU64Cost                         Gas = 1
	StoreU8Cost                         Gas = 1
	StoreU16Cost                        Gas = 1
	StoreU32Cost                        Gas = 1
	StoreU64Cost                        Gas = 1
	StoreImmIndirectU8Cost              Gas = 1
	StoreImmIndirectU16Cost             Gas = 1
	StoreImmIndirectU32Cost             Gas = 1
	StoreImmIndirectU64Cost             Gas = 1
	LoadImmAndJumpCost                  Gas = 1
	BranchEqImmCost                     Gas = 1
	BranchNotEqImmCost                  Gas = 1
	BranchLessUnsignedImmCost           Gas = 1
	BranchLessOrEqualUnsignedImmCost    Gas = 1
	BranchGreaterOrEqualUnsignedImmCost Gas = 1
	BranchGreaterUnsignedImmCost        Gas = 1
	BranchLessSignedImmCost             Gas = 1
	BranchLessOrEqualSignedImmCost      Gas = 1
	BranchGreaterOrEqualSignedImmCost   Gas = 1
	BranchGreaterSignedImmCost          Gas = 1
	MoveRegCost                         Gas = 1
	SbrkCost                            Gas = 1
	CountSetBits64Cost                  Gas = 1
	CountSetBits32Cost                  Gas = 1
	LeadingZeroBits64Cost               Gas = 1
	LeadingZeroBits32Cost               Gas = 1
	TrailingZeroBits64Cost              Gas = 1
	TrailingZeroBits32Cost              Gas = 1
	SignExtend8Cost                     Gas = 1
	SignExtend16Cost                    Gas = 1
	ZeroExtend16Cost                    Gas = 1
	ReverseBytesCost                    Gas = 1
	StoreIndirectU8Cost                 Gas = 1
	StoreIndirectU16Cost                Gas = 1
	StoreIndirectU32Cost                Gas = 1
	StoreIndirectU64Cost                Gas = 1
	LoadIndirectU8Cost                  Gas = 1
	LoadIndirectI8Cost                  Gas = 1
	LoadIndirectU16Cost                 Gas = 1
	LoadIndirectI16Cost                 Gas = 1
	LoadIndirectU32Cost                 Gas = 1
	LoadIndirectI32Cost                 Gas = 1
	LoadIndirectU64Cost                 Gas = 1
	AddImm32Cost                        Gas = 1
	AndImmCost                          Gas = 1
	XorImmCost                          Gas = 1
	OrImmCost                           Gas = 1
	MulImm32Cost                        Gas = 1
	SetLessThanUnsignedImmCost          Gas = 1
	SetLessThanSignedImmCost            Gas = 1
	ShiftLogicalLeftImm32Cost           Gas = 1
	ShiftLogicalRightImm32Cost          Gas = 1
	ShiftArithmeticRightImm32Cost       Gas = 1
	NegateAndAddImm32Cost               Gas = 1
	SetGreaterThanUnsignedImmCost       Gas = 1
	SetGreaterThanSignedImmCost         Gas = 1
	ShiftLogicalRightImmAlt32Cost       Gas = 1
	ShiftArithmeticRightImmAlt32Cost    Gas = 1
	ShiftLogicalLeftImmAlt32Cost        Gas = 1
	CmovIfZeroImmCost                   Gas = 1
	CmovIfNotZeroImmCost                Gas = 1
	AddImm64Cost                        Gas = 1
	MulImm64Cost                        Gas = 1
	ShiftLogicalLeftImm64Cost           Gas = 1
	ShiftLogicalRightImm64Cost          Gas = 1
	ShiftArithmeticRightImm64Cost       Gas = 1
	NegateAndAddImm64Cost               Gas = 1
	ShiftLogicalLeftImmAlt64Cost        Gas = 1
	ShiftLogicalRightImmAlt64Cost       Gas = 1
	ShiftArithmeticRightImmAlt64Cost    Gas = 1
	RotR64ImmCost                       Gas = 1
	RotR64ImmAltCost                    Gas = 1
	RotR32ImmCost                       Gas = 1
	RotR32ImmAltCost                    Gas = 1
	BranchEqCost                        Gas = 1
	BranchNotEqCost                     Gas = 1
	BranchLessUnsignedCost              Gas = 1
	BranchLessSignedCost                Gas = 1
	BranchGreaterOrEqualUnsignedCost    Gas = 1
	BranchGreaterOrEqualSignedCost      Gas = 1
	LoadImmAndJumpIndirectCost          Gas = 1
	Add32Cost                           Gas = 1
	Sub32Cost                           Gas = 1
	Mul32Cost                           Gas = 1
	DivUnsigned32Cost                   Gas = 1
	DivSigned32Cost                     Gas = 1
	RemUnsigned32Cost                   Gas = 1
	RemSigned32Cost                     Gas = 1
	ShiftLogicalLeft32Cost              Gas = 1
	ShiftLogicalRight32Cost             Gas = 1
	ShiftArithmeticRight32Cost          Gas = 1
	Add64Cost                           Gas = 1
	Sub64Cost                           Gas = 1
	Mul64Cost                           Gas = 1
	DivUnsigned64Cost                   Gas = 1
	DivSigned64Cost                     Gas = 1
	RemUnsigned64Cost                   Gas = 1
	RemSigned64Cost                     Gas = 1
	ShiftLogicalLeft64Cost              Gas = 1
	ShiftLogicalRight64Cost             Gas = 1
	ShiftArithmeticRight64Cost          Gas = 1
	AndCost                             Gas = 1
	XorCost                             Gas = 1
	OrCost                              Gas = 1
	MulUpperSignedSignedCost            Gas = 1
	MulUpperUnsignedUnsignedCost        Gas = 1
	MulUpperSignedUnsignedCost          Gas = 1
	SetLessThanUnsignedCost             Gas = 1
	SetLessThanSignedCost               Gas = 1
	CmovIfZeroCost                      Gas = 1
	CmovIfNotZeroCost                   Gas = 1
	RotL64Cost                          Gas = 1
	RotL32Cost                          Gas = 1
	RotR64Cost                          Gas = 1
	RotR32Cost                          Gas = 1
	AndInvCost                          Gas = 1
	OrInvCost                           Gas = 1
	XnorCost                            Gas = 1
	MaxCost                             Gas = 1
	MaxUCost                            Gas = 1
	MinCost                             Gas = 1
	MinUCost                            Gas = 1
)

type Reg byte

func (r Reg) String() string {
	switch r {
	case R0:
		return "ra"
	case R1:
		return "sp"
	case R2:
		return "t0"
	case R3:
		return "t1"
	case R4:
		return "t2"
	case R5:
		return "s0"
	case R6:
		return "s1"
	case R7:
		return "a0"
	case R8:
		return "a1"
	case R9:
		return "a2"
	case R10:
		return "a3"
	case R11:
		return "a4"
	case R12:
		return "a5"
	default:
		return "UNKNOWN"
	}
}

const (
	R0  Reg = 0
	R1  Reg = 1
	R2  Reg = 2
	R3  Reg = 3
	R4  Reg = 4
	R5  Reg = 5
	R6  Reg = 6
	R7  Reg = 7
	R8  Reg = 8
	R9  Reg = 9
	R10 Reg = 10
	R11 Reg = 11
	R12 Reg = 12
)

// IsBasicBlockTermination (eq A.3)
func (o Opcode) IsBasicBlockTermination() bool {
	switch o {
	case
		// Trap and fallthrough: trap, fallthrough
		Trap, Fallthrough,

		// Jumps: jump, jump_ind
		Jump, JumpInd,

		// Load-and-Jumps: load_imm_jump , load_imm_jump_ind
		LoadImmJump, LoadImmJumpInd,

		// Branches: branch_eq, branch_ne, branch_ge_u, branch_ge_s, branch_lt_u, branch_lt_s, branch_eq_imm, branch_ne_imm
		BranchEq, BranchNe, BranchGeU, BranchGeS,
		BranchLtU, BranchLtS, BranchEqImm, BranchNeImm,

		// Immediate branches: branch_lt_u_imm, branch_lt_s_imm, branch_le_u_imm, branch_le_s_imm, branch_ge_u_imm, branch_ge_s_imm, branch_gt_u_imm, branch_gt_s_imm
		BranchLtUImm, BranchLtSImm, BranchLeUImm, BranchLeSImm,
		BranchGeUImm, BranchGeSImm, BranchGtUImm, BranchGtSImm:
		return true
	}
	return false
}

// opcodeValid c_n ∈ U (eq A.23)
//
//nolint:unused
func opcodeValid(c Opcode) bool {
	switch c {
	case Trap, Fallthrough, Ecalli, LoadImm64, StoreImmU8, StoreImmU16, StoreImmU32, StoreImmU64, Jump,
		JumpInd, LoadImm, LoadU8, LoadI8, LoadU16, LoadI16, LoadU32, LoadI32, LoadU64, StoreU8, StoreU16, StoreU32, StoreU64,
		StoreImmIndU8, StoreImmIndU16, StoreImmIndU32, StoreImmIndU64, LoadImmJump,
		BranchEqImm, BranchNeImm, BranchLtUImm, BranchLeUImm,
		BranchGeUImm, BranchGtUImm, BranchLtSImm,
		BranchLeSImm, BranchGeSImm, BranchGtSImm,
		MoveReg, Sbrk, CountSetBits64, CountSetBits32, LeadingZeroBits64, LeadingZeroBits32,
		TrailingZeroBits64, TrailingZeroBits32, SignExtend8, SignExtend16, ZeroExtend16, ReverseBytes,
		StoreIndU8, StoreIndU16, StoreIndU32, StoreIndU64, LoadIndU8, LoadIndI8,
		LoadIndU16, LoadIndI16, LoadIndU32, LoadIndI32, LoadIndU64,
		AddImm32, AndImm, XorImm, OrImm, MulImm32, SetLtUImm, SetLtSImm,
		ShloLImm32, ShloRImm32, SharRImm32,
		NegAddImm32, SetGtUImm, SetGtSImm,
		ShloLImmAlt32, ShloRImmAlt32, SharRImmAlt32,
		CmovIzImm, CmovNzImm, AddImm64, MulImm64, ShloLImm64, ShloRImm64,
		SharRImm64, NegAddImm64, ShloLImmAlt64, ShloRImmAlt64,
		SharRImmAlt64, RotR64Imm, RotR64ImmAlt, RotR32Imm, RotR32ImmAlt, BranchEq,
		BranchNe, BranchLtU, BranchLtS, BranchGeU, BranchGeS,
		LoadImmJumpInd, Add32, Sub32, Mul32, DivU32, DivS32, RemU32, RemS32,
		ShloL32, ShloR32, SharR32, Add64, Sub64, Mul64,
		DivU64, DivS64, RemU64, RemS64, ShloL64, ShloR64,
		SharR64, And, Xor, Or, MulUpperSS, MulUpperUU, MulUpperSU,
		SetLtU, SetLtS, CmovIz, CmovNz, RotL64, RotL32, RotR64, RotR32,
		AndInv, OrInv, Xnor, Max, MaxU, Min, MinU:
		return true
	}

	return false
}
