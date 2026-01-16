package pvm

// A.5.1. Instructions without Arguments
const (
	Trap        Opcode = 0 // trap
	Fallthrough Opcode = 1 // fallthrough
	Unlikely    Opcode = 2 // unlikely
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
	JumpInd  Opcode = 50 // jump_ind
	LoadImm  Opcode = 51 // load_imm
	LoadU8   Opcode = 52 // load_u8
	LoadI8   Opcode = 53 // load_i8
	LoadU16  Opcode = 54 // load_u16
	LoadI16  Opcode = 55 // load_i16
	LoadU32  Opcode = 56 // load_u32
	LoadI32  Opcode = 57 // load_i32
	LoadU64  Opcode = 58 // load_u64
	StoreU8  Opcode = 59 // store_u8
	StoreU16 Opcode = 60 // store_u16
	StoreU32 Opcode = 61 // store_u32
	StoreU64 Opcode = 62 // store_u64
)

// A.5.7. Instructions with Arguments of One Register & Two Immediates.
const (
	StoreImmIndU8  Opcode = 70 // store_imm_ind_u8
	StoreImmIndU16 Opcode = 71 // store_imm_ind_u16
	StoreImmIndU32 Opcode = 72 // store_imm_ind_u32
	StoreImmIndU64 Opcode = 73 // store_imm_ind_u64
)

// A.5.8. Instructions with Arguments of One Register, One Immediate and One Offset.
const (
	LoadImmJump  Opcode = 80 // load_imm_jump
	BranchEqImm  Opcode = 81 // branch_eq_imm
	BranchNeImm  Opcode = 82 // branch_ne_imm
	BranchLtUImm Opcode = 83 // branch_lt_u_imm
	BranchLeUImm Opcode = 84 // branch_le_u_imm
	BranchGeUImm Opcode = 85 // branch_ge_u_imm
	BranchGtUImm Opcode = 86 // branch_gt_u_imm
	BranchLtSImm Opcode = 87 // branch_lt_s_imm
	BranchLeSImm Opcode = 88 // branch_le_s_imm
	BranchGeSImm Opcode = 89 // branch_ge_s_imm
	BranchGtSImm Opcode = 90 // branch_gt_s_imm
)

// A.5.9. Instructions with Arguments of Two Registers.
const (
	MoveReg            Opcode = 100 // move_reg
	CountSetBits64     Opcode = 101 // count_set_bits_64
	CountSetBits32     Opcode = 102 // count_set_bits_32
	LeadingZeroBits64  Opcode = 103 // leading_zero_bits_64
	LeadingZeroBits32  Opcode = 104 // leading_zero_bits_32
	TrailingZeroBits64 Opcode = 105 // trailing_zero_bits_64
	TrailingZeroBits32 Opcode = 106 // trailing_zero_bits_32
	SignExtend8        Opcode = 107 // sign_extend_8
	SignExtend16       Opcode = 108 // sign_extend_16
	ZeroExtend16       Opcode = 109 // zero_extend_16
	ReverseBytes       Opcode = 110 // reverse_bytes
)

// A.5.10. Instructions with Arguments of Two Registers & One Immediate.
const (
	StoreIndU8    Opcode = 120 // store_ind_u8
	StoreIndU16   Opcode = 121 // store_ind_u16
	StoreIndU32   Opcode = 122 // store_ind_u32
	StoreIndU64   Opcode = 123 // store_ind_u64
	LoadIndU8     Opcode = 124 // load_ind_u8
	LoadIndI8     Opcode = 125 // load_ind_i8
	LoadIndU16    Opcode = 126 // load_ind_u16
	LoadIndI16    Opcode = 127 // load_ind_i16
	LoadIndU32    Opcode = 128 // load_ind_u32
	LoadIndI32    Opcode = 129 // load_ind_i32
	LoadIndU64    Opcode = 130 // load_ind_u64
	AddImm32      Opcode = 131 // add_imm_32
	AndImm        Opcode = 132 // and_imm
	XorImm        Opcode = 133 // xor_imm
	OrImm         Opcode = 134 // or_imm
	MulImm32      Opcode = 135 // mul_imm_32
	SetLtUImm     Opcode = 136 // set_lt_u_imm
	SetLtSImm     Opcode = 137 // set_lt_s_imm
	ShloLImm32    Opcode = 138 // shlo_l_imm_32
	ShloRImm32    Opcode = 139 // shlo_r_imm_32
	SharRImm32    Opcode = 140 // shar_r_imm_32
	NegAddImm32   Opcode = 141 // neg_add_imm_32
	SetGtUImm     Opcode = 142 // set_gt_u_imm
	SetGtSImm     Opcode = 143 // set_gt_s_imm
	ShloLImmAlt32 Opcode = 144 // shlo_l_imm_alt_32
	ShloRImmAlt32 Opcode = 145 // shlo_r_imm_alt_32
	SharRImmAlt32 Opcode = 146 // shar_r_imm_alt_32
	CmovIzImm     Opcode = 147 // cmov_iz_imm
	CmovNzImm     Opcode = 148 // cmov_nz_imm
	AddImm64      Opcode = 149 // add_imm_64
	MulImm64      Opcode = 150 // mul_imm_64
	ShloLImm64    Opcode = 151 // shlo_l_imm_64
	ShloRImm64    Opcode = 152 // shlo_r_imm_64
	SharRImm64    Opcode = 153 // shar_r_imm_64
	NegAddImm64   Opcode = 154 // neg_add_imm_64
	ShloLImmAlt64 Opcode = 155 // shlo_l_imm_alt_64
	ShloRImmAlt64 Opcode = 156 // shlo_r_imm_alt_64
	SharRImmAlt64 Opcode = 157 // shar_r_imm_alt_64
	RotR64Imm     Opcode = 158 // rot_r_64_imm
	RotR64ImmAlt  Opcode = 159 // rot_r_64_imm_alt
	RotR32Imm     Opcode = 160 // rot_r_32_imm
	RotR32ImmAlt  Opcode = 161 // rot_r_32_imm_alt
)

// A.5.11. Instructions with Arguments of Two Registers & One Offset.
const (
	BranchEq  Opcode = 170 // branch_eq
	BranchNe  Opcode = 171 // branch_ne
	BranchLtU Opcode = 172 // branch_lt_u
	BranchLtS Opcode = 173 // branch_lt_s
	BranchGeU Opcode = 174 // branch_ge_u
	BranchGeS Opcode = 175 // branch_ge_s
)

// A.5.12. Instruction with Arguments of Two Registers and Two Immediates.
const (
	LoadImmJumpInd Opcode = 180 // load_imm_jump_ind
)

// A.5.13. Instructions with Arguments of Three Registers.
const (
	Add32      Opcode = 190 // add_32
	Sub32      Opcode = 191 // sub_32
	Mul32      Opcode = 192 // mul_32
	DivU32     Opcode = 193 // div_u_32
	DivS32     Opcode = 194 // div_s_32
	RemU32     Opcode = 195 // rem_u_32
	RemS32     Opcode = 196 // rem_s_32
	ShloL32    Opcode = 197 // shlo_l_32
	ShloR32    Opcode = 198 // shlo_r_32
	SharR32    Opcode = 199 // shar_r_32
	Add64      Opcode = 200 // add_64
	Sub64      Opcode = 201 // sub_64
	Mul64      Opcode = 202 // mul_64
	DivU64     Opcode = 203 // div_u_64
	DivS64     Opcode = 204 // div_s_64
	RemU64     Opcode = 205 // rem_u_64
	RemS64     Opcode = 206 // rem_s_64
	ShloL64    Opcode = 207 // shlo_l_64
	ShloR64    Opcode = 208 // shlo_r_64
	SharR64    Opcode = 209 // shar_r_64
	And        Opcode = 210 // and
	Xor        Opcode = 211 // xor
	Or         Opcode = 212 // or
	MulUpperSS Opcode = 213 // mul_upper_s_s
	MulUpperUU Opcode = 214 // mul_upper_u_u
	MulUpperSU Opcode = 215 // mul_upper_s_u
	SetLtU     Opcode = 216 // set_lt_u
	SetLtS     Opcode = 217 // set_lt_s
	CmovIz     Opcode = 218 // cmov_iz
	CmovNz     Opcode = 219 // cmov_nz
	RotL64     Opcode = 220 // rot_l_64
	RotL32     Opcode = 221 // rot_l_32
	RotR64     Opcode = 222 // rot_r_64
	RotR32     Opcode = 223 // rot_r_32
	AndInv     Opcode = 224 // and_inv
	OrInv      Opcode = 225 // or_inv
	Xnor       Opcode = 226 // xnor
	Max        Opcode = 227 // max
	MaxU       Opcode = 228 // max_u
	Min        Opcode = 229 // min
	MinU       Opcode = 230 // min_u
)
