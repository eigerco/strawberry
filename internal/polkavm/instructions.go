package polkavm

import (
	"encoding/binary"
	"fmt"
)

type Opcode byte

const (
	// A.5.1. Instructions without Arguments
	Trap        Opcode = 0  // trap = 0
	Fallthrough Opcode = 17 // fallthrough = 1

	// A.5.2. Instructions with Arguments of One Immediate.
	Ecalli Opcode = 78 // ecalli = 10

	// A.5.3. Instructions with Arguments of One Register and One Extended Width Immediate.
	LoadImm64 = 255 - 20 // load_imm_64 = 20

	// A.5.4. Instructions with Arguments of Two Immediates.
	StoreImmU8  Opcode = 62       // store_imm_u8 = 30
	StoreImmU16 Opcode = 79       // store_imm_u16 = 31
	StoreImmU32 Opcode = 38       // store_imm_u32 = 32
	StoreImmU64 Opcode = 255 - 33 // store_imm_u64 = 33

	// A.5.5. Instructions with Arguments of One Offset.
	Jump Opcode = 5

	// A.5.6. Instructions with Arguments of One Register & One Immediate.
	JumpIndirect Opcode = 19       // jump_ind = 50
	LoadImm      Opcode = 4        // load_imm = 51
	LoadU8       Opcode = 60       // load_u8 = 52
	LoadI8       Opcode = 74       // load_i8 = 53
	LoadU16      Opcode = 76       // load_u16 = 54
	LoadI16      Opcode = 66       // load_i16 = 55
	LoadU32      Opcode = 10       // load_u32 = 56
	LoadI32      Opcode = 255 - 57 // load_i32 = 57
	LoadU64      Opcode = 255 - 58 // load_u64 = 58
	StoreU8      Opcode = 71       // store_u8 = 59
	StoreU16     Opcode = 69       // store_u16 = 60
	StoreU32     Opcode = 22       // store_u32 = 61
	StoreU64     Opcode = 255 - 62 // store_u64 = 62

	// A.5.7. Instructions with Arguments of One Register & Two Immediates.
	StoreImmIndirectU8  Opcode = 26       // store_imm_ind_u8 = 70
	StoreImmIndirectU16 Opcode = 54       // store_imm_ind_u16 = 71
	StoreImmIndirectU32 Opcode = 13       // store_imm_ind_u32 = 72
	StoreImmIndirectU64 Opcode = 300 - 73 // store_imm_ind_u64 = 73 // todo fix opcode numbers

	// A.5.8. Instructions with Arguments of One Register, One Immediate and One Offset.
	LoadImmAndJump                  Opcode = 6  // load_imm_jump = 80
	BranchEqImm                     Opcode = 7  // branch_eq_imm = 81
	BranchNotEqImm                  Opcode = 15 // branch_ne_imm = 82
	BranchLessUnsignedImm           Opcode = 44 // branch_lt_u_imm = 83
	BranchLessOrEqualUnsignedImm    Opcode = 59 // branch_le_u_imm = 84
	BranchGreaterOrEqualUnsignedImm Opcode = 52 // branch_ge_u_imm = 85
	BranchGreaterUnsignedImm        Opcode = 50 // branch_gt_u_imm = 86
	BranchLessSignedImm             Opcode = 32 // branch_lt_s_imm = 87
	BranchLessOrEqualSignedImm      Opcode = 46 // branch_le_s_imm = 88
	BranchGreaterOrEqualSignedImm   Opcode = 45 // branch_ge_s_imm = 89
	BranchGreaterSignedImm          Opcode = 53 // branch_gt_s_imm = 90

	// A.5.9. Instructions with Arguments of Two Registers.
	MoveReg Opcode = 82 // move_reg = 100
	Sbrk    Opcode = 87 // sbrk = 101

	// A.5.10. Instructions with Arguments of Two Registers & One Immediate.
	StoreIndirectU8              Opcode = 16        // store_ind_u8 = 110
	StoreIndirectU16             Opcode = 29        // store_ind_u16 = 111
	StoreIndirectU32             Opcode = 3         // store_ind_u32 = 112
	StoreIndirectU64             Opcode = 350 - 113 // store_ind_u64 = 113 // todo fix opcode numbers
	LoadIndirectU8               Opcode = 11        // load_ind_u8 = 114
	LoadIndirectI8               Opcode = 21        // load_ind_i8 = 115
	LoadIndirectU16              Opcode = 37        // load_ind_u16 = 116
	LoadIndirectI16              Opcode = 33        // load_ind_i16 = 117
	LoadIndirectU32              Opcode = 1         // load_ind_u32 = 118
	LoadIndirectI32              Opcode = 255 - 119 // load_ind_i32 = 119
	LoadIndirectU64              Opcode = 255 - 120 // load_ind_u64 = 120
	AddImm32                     Opcode = 2         // add_imm_32 = 121
	AndImm                       Opcode = 18        // and_imm = 122
	XorImm                       Opcode = 31        // xor_imm = 123
	OrImm                        Opcode = 49        // or_imm = 124
	MulImm32                     Opcode = 35        // mul_imm_32 = 125
	SetLessThanUnsignedImm       Opcode = 27        // set_lt_u_imm = 126
	SetLessThanSignedImm         Opcode = 56        // set_lt_s_imm = 127
	ShiftLogicalLeftImm32        Opcode = 9         // shlo_l_imm_32 = 128
	ShiftLogicalRightImm32       Opcode = 14        // shlo_r_imm_32 = 129
	ShiftArithmeticRightImm32    Opcode = 25        // shar_r_imm_32 = 130
	NegateAndAddImm32            Opcode = 40        // neg_add_imm_32 = 131
	SetGreaterThanUnsignedImm    Opcode = 39        // set_gt_u_imm = 132
	SetGreaterThanSignedImm      Opcode = 61        // set_gt_s_imm = 133
	ShiftLogicalRightImmAlt32    Opcode = 72        // shlo_r_imm_alt_32 = 134
	ShiftArithmeticRightImmAlt32 Opcode = 80        // shar_r_imm_alt_32 = 135
	ShiftLogicalLeftImmAlt32     Opcode = 75        // shlo_l_imm_alt_32 = 136
	CmovIfZeroImm                Opcode = 85        // cmov_iz_imm = 137
	CmovIfNotZeroImm             Opcode = 86        // cmov_nz_imm = 138
	AddImm64                     Opcode = 139       // add_imm_64 = 139
	MulImm64                     Opcode = 140       // mul_imm_64 = 140
	ShiftLogicalLeftImm64        Opcode = 141       // shlo_l_imm_64 = 141
	ShiftLogicalRightImm64       Opcode = 142       // shlo_r_imm_64 = 142
	ShiftArithmeticRightImm64    Opcode = 143       // shar_r_imm_64 = 143
	NegateAndAddImm64            Opcode = 144       // neg_add_imm_64 = 144
	ShiftLogicalLeftImmAlt64     Opcode = 145       // shlo_l_imm_alt_64 = 145
	ShiftLogicalRightImmAlt64    Opcode = 146       // shlo_r_imm_alt_64 = 146
	ShiftArithmeticRightImmAlt64 Opcode = 147       // shar_r_imm_alt_64 = 147

	// A.5.11. Instructions with Arguments of Two Registers & One Offset.
	BranchEq                     Opcode = 24 // branch_eq = 150
	BranchNotEq                  Opcode = 30 // branch_ne = 151
	BranchLessUnsigned           Opcode = 47 // branch_lt_u = 152
	BranchLessSigned             Opcode = 48 // branch_lt_s = 153
	BranchGreaterOrEqualUnsigned Opcode = 41 // branch_ge_u = 154
	BranchGreaterOrEqualSigned   Opcode = 43 // branch_ge_s = 155

	// A.5.12. Instruction with Arguments of Two Registers and Two Immediates.
	LoadImmAndJumpIndirect Opcode = 42 // load_imm_jump_ind = 160

	// A.5.13. Instructions with Arguments of Three Registers.
	Add32                    Opcode = 8   // add_32 = 170
	Sub32                    Opcode = 20  // sub_32 = 171
	Mul32                    Opcode = 34  // mul_32 = 172
	DivUnsigned32            Opcode = 68  // div_u_32 = 173
	DivSigned32              Opcode = 64  // div_s_32 = 174
	RemUnsigned32            Opcode = 73  // rem_u_32 = 175
	RemSigned32              Opcode = 70  // rem_s_32 = 176
	ShiftLogicalLeft32       Opcode = 55  // shlo_l_32 = 177
	ShiftLogicalRight32      Opcode = 51  // shlo_r_32 = 178
	ShiftArithmeticRight32   Opcode = 77  // shar_r_32 = 179
	Add64                    Opcode = 180 // add_64 = 180
	Sub64                    Opcode = 181 // sub_64 = 181
	Mul64                    Opcode = 182 // mul_64 = 182
	DivUnsigned64            Opcode = 183 // div_u_64 = 183
	DivSigned64              Opcode = 184 // div_s_64 = 184
	RemUnsigned64            Opcode = 185 // rem_u_64 = 185
	RemSigned64              Opcode = 186 // rem_s_64 = 186
	ShiftLogicalLeft64       Opcode = 187 // shlo_l_64 = 187
	ShiftLogicalRight64      Opcode = 188 // shlo_r_64 = 188
	ShiftArithmeticRight64   Opcode = 189 // shar_r_64 = 189
	And                      Opcode = 23  // and = 190
	Xor                      Opcode = 28  // xor = 191
	Or                       Opcode = 12  // or = 192
	MulUpperSignedSigned     Opcode = 67  // mul_upper_s_s = 193
	MulUpperUnsignedUnsigned Opcode = 57  // mul_upper_u_u = 194
	MulUpperSignedUnsigned   Opcode = 81  // mul_upper_s_u = 195
	SetLessThanUnsigned      Opcode = 36  // set_lt_u = 196
	SetLessThanSigned        Opcode = 58  // set_lt_s = 197
	CmovIfZero               Opcode = 83  // cmov_iz = 198
	CmovIfNotZero            Opcode = 84  // cmov_nz = 199
)

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
	instrRegReg = []Opcode{MoveReg, Sbrk}
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
	}
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
	for _, code := range instrRegImmExt {
		parseArgsTable[code] = func(chunk []byte, instructionOffset, argsLength uint32) ([]Reg, []uint32) {
			// TODO parse extended immediate
			return nil, nil
		}
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
		return uint32(binary.LittleEndian.Uint16([]byte{slice[0], slice[1]}))
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
