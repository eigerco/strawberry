//go:build !integration

package polkavm

// A.5.1. Instructions without Arguments
const (
	Trap        Opcode = 0 // trap
	Fallthrough Opcode = 1 // fallthrough
)

// A.5.2. Instructions with Arguments of One Immediate.
const (
	Ecalli Opcode = 10 // ecalli
)

// A.5.3. Instructions with Arguments of One Register and One Extended Width Immediate.
const (
	LoadImm64 Opcode = 20 // load_imm_64
)

// A.5.4. Instructions with Arguments of Two Immediates.
const (
	StoreImmU8  Opcode = 30 // store_imm_u8
	StoreImmU16 Opcode = 31 // store_imm_u16
	StoreImmU32 Opcode = 32 // store_imm_u32
	StoreImmU64 Opcode = 33 // store_imm_u64
)

// A.5.5. Instructions with Arguments of One Offset.
const (
	Jump Opcode = 40
)

// A.5.6. Instructions with Arguments of One Register & One Immediate.
const (
	JumpIndirect Opcode = 50 // jump_ind
	LoadImm      Opcode = 51 // load_imm
	LoadU8       Opcode = 52 // load_u8
	LoadI8       Opcode = 53 // load_i8
	LoadU16      Opcode = 54 // load_u16
	LoadI16      Opcode = 55 // load_i16
	LoadU32      Opcode = 56 // load_u32
	LoadI32      Opcode = 57 // load_i32
	LoadU64      Opcode = 58 // load_u64
	StoreU8      Opcode = 59 // store_u8
	StoreU16     Opcode = 60 // store_u16
	StoreU32     Opcode = 61 // store_u32
	StoreU64     Opcode = 62 // store_u64
)

// A.5.7. Instructions with Arguments of One Register & Two Immediates.
const (
	StoreImmIndirectU8  Opcode = 70 // store_imm_ind_u8
	StoreImmIndirectU16 Opcode = 71 // store_imm_ind_u16
	StoreImmIndirectU32 Opcode = 72 // store_imm_ind_u32
	StoreImmIndirectU64 Opcode = 73 // store_imm_ind_u64
)

// A.5.8. Instructions with Arguments of One Register, One Immediate and One Offset.
const (
	LoadImmAndJump                  Opcode = 80 // load_imm_jump
	BranchEqImm                     Opcode = 81 // branch_eq_imm
	BranchNotEqImm                  Opcode = 82 // branch_ne_imm
	BranchLessUnsignedImm           Opcode = 83 // branch_lt_u_imm
	BranchLessOrEqualUnsignedImm    Opcode = 84 // branch_le_u_imm
	BranchGreaterOrEqualUnsignedImm Opcode = 85 // branch_ge_u_imm
	BranchGreaterUnsignedImm        Opcode = 86 // branch_gt_u_imm
	BranchLessSignedImm             Opcode = 87 // branch_lt_s_imm
	BranchLessOrEqualSignedImm      Opcode = 88 // branch_le_s_imm
	BranchGreaterOrEqualSignedImm   Opcode = 89 // branch_ge_s_imm
	BranchGreaterSignedImm          Opcode = 90 // branch_gt_s_imm
)

// A.5.9. Instructions with Arguments of Two Registers.
const (
	MoveReg            Opcode = 100 // move_reg
	Sbrk               Opcode = 101 // sbrk
	CountSetBits64     Opcode = 102 // count_set_bits_64
	CountSetBits32     Opcode = 103 // count_set_bits_32
	LeadingZeroBits64  Opcode = 104 // leading_zero_bits_64
	LeadingZeroBits32  Opcode = 105 // leading_zero_bits_32
	TrailingZeroBits64 Opcode = 106 // trailing_zero_bits_64
	TrailingZeroBits32 Opcode = 107 // trailing_zero_bits_32
	SignExtend8        Opcode = 108 // sign_extend_8
	SignExtend16       Opcode = 109 // sign_extend_16
	ZeroExtend16       Opcode = 110 // zero_extend_16
	ReverseBytes       Opcode = 111 // reverse_bytes
)

// A.5.10. Instructions with Arguments of Two Registers & One Immediate.
const (
	StoreIndirectU8              Opcode = 120 // store_ind_u8
	StoreIndirectU16             Opcode = 121 // store_ind_u16
	StoreIndirectU32             Opcode = 122 // store_ind_u32
	StoreIndirectU64             Opcode = 123 // store_ind_u64
	LoadIndirectU8               Opcode = 124 // load_ind_u8
	LoadIndirectI8               Opcode = 125 // load_ind_i8
	LoadIndirectU16              Opcode = 126 // load_ind_u16
	LoadIndirectI16              Opcode = 127 // load_ind_i16
	LoadIndirectU32              Opcode = 128 // load_ind_u32
	LoadIndirectI32              Opcode = 129 // load_ind_i32
	LoadIndirectU64              Opcode = 130 // load_ind_u64
	AddImm32                     Opcode = 131 // add_imm_32
	AndImm                       Opcode = 132 // and_imm
	XorImm                       Opcode = 133 // xor_imm
	OrImm                        Opcode = 134 // or_imm
	MulImm32                     Opcode = 135 // mul_imm_32
	SetLessThanUnsignedImm       Opcode = 136 // set_lt_u_imm
	SetLessThanSignedImm         Opcode = 137 // set_lt_s_imm
	ShiftLogicalLeftImm32        Opcode = 138 // shlo_l_imm_32
	ShiftLogicalRightImm32       Opcode = 139 // shlo_r_imm_32
	ShiftArithmeticRightImm32    Opcode = 140 // shar_r_imm_32
	NegateAndAddImm32            Opcode = 141 // neg_add_imm_32
	SetGreaterThanUnsignedImm    Opcode = 142 // set_gt_u_imm
	SetGreaterThanSignedImm      Opcode = 143 // set_gt_s_imm
	ShiftLogicalLeftImmAlt32     Opcode = 144 // shlo_l_imm_alt_32
	ShiftArithmeticRightImmAlt32 Opcode = 145 // shlo_r_imm_alt_32
	ShiftLogicalRightImmAlt32    Opcode = 146 // shar_r_imm_alt_32
	CmovIfZeroImm                Opcode = 147 // cmov_iz_imm
	CmovIfNotZeroImm             Opcode = 148 // cmov_nz_imm
	AddImm64                     Opcode = 149 // add_imm_64
	MulImm64                     Opcode = 150 // mul_imm_64
	ShiftLogicalLeftImm64        Opcode = 151 // shlo_l_imm_64
	ShiftLogicalRightImm64       Opcode = 152 // shlo_r_imm_64
	ShiftArithmeticRightImm64    Opcode = 153 // shar_r_imm_64
	NegateAndAddImm64            Opcode = 154 // neg_add_imm_64
	ShiftLogicalLeftImmAlt64     Opcode = 155 // shlo_l_imm_alt_64
	ShiftLogicalRightImmAlt64    Opcode = 156 // shlo_r_imm_alt_64
	ShiftArithmeticRightImmAlt64 Opcode = 157 // shar_r_imm_alt_64
	RotR64Imm                    Opcode = 158 // rot_r_64_imm
	RotR64ImmAlt                 Opcode = 159 // rot_r_64_imm_alt
	RotR32Imm                    Opcode = 160 // rot_r_32_imm
	RotR32ImmAlt                 Opcode = 161 // rot_r_32_imm_alt
)

// A.5.11. Instructions with Arguments of Two Registers & One Offset.
const (
	BranchEq                     Opcode = 170 // branch_eq
	BranchNotEq                  Opcode = 171 // branch_ne
	BranchLessUnsigned           Opcode = 172 // branch_lt_u
	BranchLessSigned             Opcode = 173 // branch_lt_s
	BranchGreaterOrEqualUnsigned Opcode = 174 // branch_ge_u
	BranchGreaterOrEqualSigned   Opcode = 175 // branch_ge_s
)

// A.5.12. Instruction with Arguments of Two Registers and Two Immediates.
const (
	LoadImmAndJumpIndirect Opcode = 180 // load_imm_jump_ind
)

// A.5.13. Instructions with Arguments of Three Registers.
const (
	Add32                    Opcode = 190 // add_32
	Sub32                    Opcode = 191 // sub_32
	Mul32                    Opcode = 192 // mul_32
	DivUnsigned32            Opcode = 193 // div_u_32
	DivSigned32              Opcode = 194 // div_s_32
	RemUnsigned32            Opcode = 195 // rem_u_32
	RemSigned32              Opcode = 196 // rem_s_32
	ShiftLogicalLeft32       Opcode = 197 // shlo_l_32
	ShiftLogicalRight32      Opcode = 198 // shlo_r_32
	ShiftArithmeticRight32   Opcode = 199 // shar_r_32
	Add64                    Opcode = 200 // add_64
	Sub64                    Opcode = 201 // sub_64
	Mul64                    Opcode = 202 // mul_64
	DivUnsigned64            Opcode = 203 // div_u_64
	DivSigned64              Opcode = 204 // div_s_64
	RemUnsigned64            Opcode = 205 // rem_u_64
	RemSigned64              Opcode = 206 // rem_s_64
	ShiftLogicalLeft64       Opcode = 207 // shlo_l_64
	ShiftLogicalRight64      Opcode = 208 // shlo_r_64
	ShiftArithmeticRight64   Opcode = 209 // shar_r_64
	And                      Opcode = 210 // and
	Xor                      Opcode = 211 // xor
	Or                       Opcode = 212 // or
	MulUpperSignedSigned     Opcode = 213 // mul_upper_s_s
	MulUpperUnsignedUnsigned Opcode = 214 // mul_upper_u_u
	MulUpperSignedUnsigned   Opcode = 215 // mul_upper_s_u
	SetLessThanUnsigned      Opcode = 216 // set_lt_u
	SetLessThanSigned        Opcode = 217 // set_lt_s
	CmovIfZero               Opcode = 218 // cmov_iz
	CmovIfNotZero            Opcode = 219 // cmov_nz
	RotL64                   Opcode = 220 // rot_l_64
	RotL32                   Opcode = 221 // rot_l_32
	RotR64                   Opcode = 222 // rot_r_64
	RotR32                   Opcode = 223 // rot_r_32
	AndInv                   Opcode = 224 // and_inv
	OrInv                    Opcode = 225 // or_inv
	Xnor                     Opcode = 226 // xnor
	Max                      Opcode = 227 // max
	MaxU                     Opcode = 228 // max_u
	Min                      Opcode = 229 // min
	MinU                     Opcode = 230 // min_u
)
