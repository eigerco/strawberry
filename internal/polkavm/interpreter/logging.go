package interpreter

import (
	"github.com/eigerco/strawberry/internal/polkavm"
	"github.com/rs/zerolog"
)

func NewLogger(m *Instance, log *zerolog.Logger) polkavm.Mutator {
	return &logger{
		m:     m,
		log:   log,
		level: zerolog.DebugLevel,
	}
}

type logger struct {
	m     *Instance
	log   *zerolog.Logger
	level zerolog.Level
}

func (l *logger) Trap() error {
	l.log.WithLevel(l.level).Msgf("%d: trap", l.m.instructionCounter)
	return l.m.Trap()
}
func (l *logger) Fallthrough() {
	l.log.WithLevel(l.level).Msgf("%d: fallthrough", l.m.instructionCounter)
	l.m.Fallthrough()
}
func (l *logger) LoadImm64(r1 polkavm.Reg, v1 uint64) {
	l.log.WithLevel(l.level).Msgf("%d: load_imm_64 %s=0x%x v1=0x%x", l.m.instructionCounter, r1, l.m.regs[r1], v1)
	l.m.LoadImm64(r1, v1)
}
func (l *logger) StoreImmU8(v1 uint64, v2 uint64) error {
	l.log.WithLevel(l.level).Msgf("%d: store_imm_u8 v1=0x%x v2=0x%x", l.m.instructionCounter, v1, v2)
	return l.m.StoreImmU8(v1, v2)
}
func (l *logger) StoreImmU16(v1 uint64, v2 uint64) error {
	l.log.WithLevel(l.level).Msgf("%d: store_imm_u16 v1=0x%x v2=0x%x", l.m.instructionCounter, v1, v2)
	return l.m.StoreImmU16(v1, v2)
}
func (l *logger) StoreImmU32(v1 uint64, v2 uint64) error {
	l.log.WithLevel(l.level).Msgf("%d: store_imm_u32 v1=0x%x v2=0x%x", l.m.instructionCounter, v1, v2)
	return l.m.StoreImmU32(v1, v2)
}
func (l *logger) StoreImmU64(v1 uint64, v2 uint64) error {
	l.log.WithLevel(l.level).Msgf("%d: store_imm_u64 v1=0x%x v2=0x%x", l.m.instructionCounter, v1, v2)
	return l.m.StoreImmU64(v1, v2)
}
func (l *logger) Jump(v1 uint64) error {
	l.log.WithLevel(l.level).Msgf("%d: jump v1=0x%x", l.m.instructionCounter, v1)
	return l.m.Jump(v1)
}
func (l *logger) JumpIndirect(r1 polkavm.Reg, v1 uint64) error {
	l.log.WithLevel(l.level).Msgf("%d: jump_ind %s=0x%x v1=0x%x", l.m.instructionCounter, r1, l.m.regs[r1], v1)
	return l.m.JumpIndirect(r1, v1)
}
func (l *logger) LoadImm(r1 polkavm.Reg, v1 uint64) {
	l.log.WithLevel(l.level).Msgf("%d: load_imm %s=0x%x v1=0x%x", l.m.instructionCounter, r1, l.m.regs[r1], v1)
	l.m.LoadImm(r1, v1)
}
func (l *logger) LoadU8(r1 polkavm.Reg, v1 uint64) error {
	l.log.WithLevel(l.level).Msgf("%d: load_u8 %s=0x%x v1=0x%x", l.m.instructionCounter, r1, l.m.regs[r1], v1)
	return l.m.LoadU8(r1, v1)
}
func (l *logger) LoadI8(r1 polkavm.Reg, v1 uint64) error {
	l.log.WithLevel(l.level).Msgf("%d: load_i8 %s=0x%x v1=0x%x", l.m.instructionCounter, r1, l.m.regs[r1], v1)
	return l.m.LoadI8(r1, v1)
}
func (l *logger) LoadU16(r1 polkavm.Reg, v1 uint64) error {
	l.log.WithLevel(l.level).Msgf("%d: load_u16 %s=0x%x v1=0x%x", l.m.instructionCounter, r1, l.m.regs[r1], v1)
	return l.m.LoadU16(r1, v1)
}
func (l *logger) LoadI16(r1 polkavm.Reg, v1 uint64) error {
	l.log.WithLevel(l.level).Msgf("%d: load_i16 %s=0x%x v1=0x%x", l.m.instructionCounter, r1, l.m.regs[r1], v1)
	return l.m.LoadI16(r1, v1)
}
func (l *logger) LoadU32(r1 polkavm.Reg, v1 uint64) error {
	l.log.WithLevel(l.level).Msgf("%d: load_u32 %s=0x%x v1=0x%x", l.m.instructionCounter, r1, l.m.regs[r1], v1)
	return l.m.LoadU32(r1, v1)
}
func (l *logger) LoadI32(r1 polkavm.Reg, v1 uint64) error {
	l.log.WithLevel(l.level).Msgf("%d: load_i32 %s=0x%x v1=0x%x", l.m.instructionCounter, r1, l.m.regs[r1], v1)
	return l.m.LoadI32(r1, v1)
}
func (l *logger) LoadU64(r1 polkavm.Reg, v1 uint64) error {
	l.log.WithLevel(l.level).Msgf("%d: load_u64 %s=0x%x v1=0x%x", l.m.instructionCounter, r1, l.m.regs[r1], v1)
	return l.m.LoadU64(r1, v1)
}
func (l *logger) StoreU8(r1 polkavm.Reg, v1 uint64) error {
	l.log.WithLevel(l.level).Msgf("%d: store_u8 %s=0x%x v1=0x%x", l.m.instructionCounter, r1, l.m.regs[r1], v1)
	return l.m.StoreU8(r1, v1)
}
func (l *logger) StoreU16(r1 polkavm.Reg, v1 uint64) error {
	l.log.WithLevel(l.level).Msgf("%d: store_u16 %s=0x%x v1=0x%x", l.m.instructionCounter, r1, l.m.regs[r1], v1)
	return l.m.StoreU16(r1, v1)
}
func (l *logger) StoreU32(r1 polkavm.Reg, v1 uint64) error {
	l.log.WithLevel(l.level).Msgf("%d: store_u32 %s=0x%x v1=0x%x", l.m.instructionCounter, r1, l.m.regs[r1], v1)
	return l.m.StoreU32(r1, v1)
}
func (l *logger) StoreU64(r1 polkavm.Reg, v1 uint64) error {
	l.log.WithLevel(l.level).Msgf("%d: store_u64 %s=0x%x v1=0x%x", l.m.instructionCounter, r1, l.m.regs[r1], v1)
	return l.m.StoreU64(r1, v1)
}

func (l *logger) StoreImmIndirectU8(r1 polkavm.Reg, v1 uint64, v2 uint64) error {
	l.log.WithLevel(l.level).Msgf("%d: store_imm_ind_u8 %s=0x%x v1=0x%x v2=0x%x", l.m.instructionCounter, r1, l.m.regs[r1], v1, v2)
	return l.m.StoreImmIndirectU8(r1, v1, v2)
}
func (l *logger) StoreImmIndirectU16(r1 polkavm.Reg, v1 uint64, v2 uint64) error {
	l.log.WithLevel(l.level).Msgf("%d: store_imm_ind_u16 %s=0x%x v1=0x%x v2=0x%x", l.m.instructionCounter, r1, l.m.regs[r1], v1, v2)
	return l.m.StoreImmIndirectU16(r1, v1, v2)
}
func (l *logger) StoreImmIndirectU32(r1 polkavm.Reg, v1 uint64, v2 uint64) error {
	l.log.WithLevel(l.level).Msgf("%d: store_imm_ind_u32 %s=0x%x v1=0x%x v2=0x%x", l.m.instructionCounter, r1, l.m.regs[r1], v1, v2)
	return l.m.StoreImmIndirectU32(r1, v1, v2)
}
func (l *logger) StoreImmIndirectU64(r1 polkavm.Reg, v1 uint64, v2 uint64) error {
	l.log.WithLevel(l.level).Msgf("%d: store_imm_ind_u64 %s=0x%x v1=0x%x v2=0x%x", l.m.instructionCounter, r1, l.m.regs[r1], v1, v2)
	return l.m.StoreImmIndirectU64(r1, v1, v2)
}

func (l *logger) LoadImmAndJump(r1 polkavm.Reg, v1 uint64, v2 uint64) error {
	l.log.WithLevel(l.level).Msgf("%d: load_imm_jump %s=0x%x v1=0x%x v2=0x%x", l.m.instructionCounter, r1, l.m.regs[r1], v1, v2)
	return l.m.LoadImmAndJump(r1, v1, v2)
}
func (l *logger) BranchEqImm(r1 polkavm.Reg, v1 uint64, v2 uint64) error {
	l.log.WithLevel(l.level).Msgf("%d: branch_eq_imm %s=0x%x v1=0x%x v2=0x%x", l.m.instructionCounter, r1, l.m.regs[r1], v1, v2)
	return l.m.BranchEqImm(r1, v1, v2)
}
func (l *logger) BranchNotEqImm(r1 polkavm.Reg, v1 uint64, v2 uint64) error {
	l.log.WithLevel(l.level).Msgf("%d: branch_ne_imm %s=0x%x v1=0x%x v2=0x%x", l.m.instructionCounter, r1, l.m.regs[r1], v1, v2)
	return l.m.BranchNotEqImm(r1, v1, v2)
}
func (l *logger) BranchLessUnsignedImm(r1 polkavm.Reg, v1 uint64, v2 uint64) error {
	l.log.WithLevel(l.level).Msgf("%d: branch_lt_u_imm %s=0x%x v1=0x%x v2=0x%x", l.m.instructionCounter, r1, l.m.regs[r1], v1, v2)
	return l.m.BranchLessUnsignedImm(r1, v1, v2)
}
func (l *logger) BranchLessOrEqualUnsignedImm(r1 polkavm.Reg, v1 uint64, v2 uint64) error {
	l.log.WithLevel(l.level).Msgf("%d: branch_le_u_imm %s=0x%x v1=0x%x v2=0x%x", l.m.instructionCounter, r1, l.m.regs[r1], v1, v2)
	return l.m.BranchLessOrEqualUnsignedImm(r1, v1, v2)
}
func (l *logger) BranchGreaterOrEqualUnsignedImm(r1 polkavm.Reg, v1 uint64, v2 uint64) error {
	l.log.WithLevel(l.level).Msgf("%d: branch_ge_u_imm %s=0x%x v1=0x%x v2=0x%x", l.m.instructionCounter, r1, l.m.regs[r1], v1, v2)
	return l.m.BranchGreaterOrEqualUnsignedImm(r1, v1, v2)
}
func (l *logger) BranchGreaterUnsignedImm(r1 polkavm.Reg, v1 uint64, v2 uint64) error {
	l.log.WithLevel(l.level).Msgf("%d: branch_gt_u_imm %s=0x%x v1=0x%x v2=0x%x", l.m.instructionCounter, r1, l.m.regs[r1], v1, v2)
	return l.m.BranchGreaterUnsignedImm(r1, v1, v2)
}
func (l *logger) BranchLessSignedImm(r1 polkavm.Reg, v1 uint64, v2 uint64) error {
	l.log.WithLevel(l.level).Msgf("%d: branch_lt_s_imm %s=0x%x v1=0x%x v2=0x%x", l.m.instructionCounter, r1, l.m.regs[r1], v1, v2)
	return l.m.BranchLessSignedImm(r1, v1, v2)
}
func (l *logger) BranchLessOrEqualSignedImm(r1 polkavm.Reg, v1 uint64, v2 uint64) error {
	l.log.WithLevel(l.level).Msgf("%d: branch_le_s_imm %s=0x%x v1=0x%x v2=0x%x", l.m.instructionCounter, r1, l.m.regs[r1], v1, v2)
	return l.m.BranchLessOrEqualSignedImm(r1, v1, v2)
}
func (l *logger) BranchGreaterOrEqualSignedImm(r1 polkavm.Reg, v1 uint64, v2 uint64) error {
	l.log.WithLevel(l.level).Msgf("%d: branch_ge_s_imm %s=0x%x v1=0x%x v2=0x%x", l.m.instructionCounter, r1, l.m.regs[r1], v1, v2)
	return l.m.BranchGreaterOrEqualSignedImm(r1, v1, v2)
}
func (l *logger) BranchGreaterSignedImm(r1 polkavm.Reg, v1 uint64, v2 uint64) error {
	l.log.WithLevel(l.level).Msgf("%d: branch_gt_s_imm %s=0x%x v1=0x%x v2=0x%x", l.m.instructionCounter, r1, l.m.regs[r1], v1, v2)
	return l.m.BranchGreaterSignedImm(r1, v1, v2)
}

func (l *logger) MoveReg(r1 polkavm.Reg, r2 polkavm.Reg) {
	l.log.WithLevel(l.level).Msgf("%d: move_reg %s=0x%x %s=0x%x", l.m.instructionCounter, r1, l.m.regs[r1], r2, l.m.regs[r2])
	l.m.MoveReg(r1, r2)
}
func (l *logger) Sbrk(r1 polkavm.Reg, r2 polkavm.Reg) error {
	l.log.WithLevel(l.level).Msgf("%d: sbrk %s=0x%x %s=0x%x", l.m.instructionCounter, r1, l.m.regs[r1], r2, l.m.regs[r2])
	return l.m.Sbrk(r1, r2)
}
func (l *logger) CountSetBits64(r1 polkavm.Reg, r2 polkavm.Reg) {
	l.log.WithLevel(l.level).Msgf("%d: count_set_bits_64 %s=0x%x %s=0x%x", l.m.instructionCounter, r1, l.m.regs[r1], r2, l.m.regs[r2])
	l.m.CountSetBits64(r1, r2)
}
func (l *logger) CountSetBits32(r1 polkavm.Reg, r2 polkavm.Reg) {
	l.log.WithLevel(l.level).Msgf("%d: count_set_bits_32 %s=0x%x %s=0x%x", l.m.instructionCounter, r1, l.m.regs[r1], r2, l.m.regs[r2])
	l.m.CountSetBits32(r1, r2)
}
func (l *logger) LeadingZeroBits64(r1 polkavm.Reg, r2 polkavm.Reg) {
	l.log.WithLevel(l.level).Msgf("%d: leading_zero_bits_64 %s=0x%x %s=0x%x", l.m.instructionCounter, r1, l.m.regs[r1], r2, l.m.regs[r2])
	l.m.LeadingZeroBits64(r1, r2)
}
func (l *logger) LeadingZeroBits32(r1 polkavm.Reg, r2 polkavm.Reg) {
	l.log.WithLevel(l.level).Msgf("%d: leading_zero_bits_32 %s=0x%x %s=0x%x", l.m.instructionCounter, r1, l.m.regs[r1], r2, l.m.regs[r2])
	l.m.LeadingZeroBits32(r1, r2)
}
func (l *logger) TrailingZeroBits64(r1 polkavm.Reg, r2 polkavm.Reg) {
	l.log.WithLevel(l.level).Msgf("%d: trailing_zero_bits_64 %s=0x%x %s=0x%x", l.m.instructionCounter, r1, l.m.regs[r1], r2, l.m.regs[r2])
	l.m.TrailingZeroBits64(r1, r2)
}
func (l *logger) TrailingZeroBits32(r1 polkavm.Reg, r2 polkavm.Reg) {
	l.log.WithLevel(l.level).Msgf("%d: trailing_zero_bits_32 %s=0x%x %s=0x%x", l.m.instructionCounter, r1, l.m.regs[r1], r2, l.m.regs[r2])
	l.m.TrailingZeroBits32(r1, r2)
}
func (l *logger) SignExtend8(r1 polkavm.Reg, r2 polkavm.Reg) {
	l.log.WithLevel(l.level).Msgf("%d: sign_extend_8 %s=0x%x %s=0x%x", l.m.instructionCounter, r1, l.m.regs[r1], r2, l.m.regs[r2])
	l.m.SignExtend8(r1, r2)
}
func (l *logger) SignExtend16(r1 polkavm.Reg, r2 polkavm.Reg) {
	l.log.WithLevel(l.level).Msgf("%d: sign_extend_16 %s=0x%x %s=0x%x", l.m.instructionCounter, r1, l.m.regs[r1], r2, l.m.regs[r2])
	l.m.SignExtend16(r1, r2)
}
func (l *logger) ZeroExtend16(r1 polkavm.Reg, r2 polkavm.Reg) {
	l.log.WithLevel(l.level).Msgf("%d: zero_extend_16 %s=0x%x %s=0x%x", l.m.instructionCounter, r1, l.m.regs[r1], r2, l.m.regs[r2])
	l.m.ZeroExtend16(r1, r2)
}
func (l *logger) ReverseBytes(r1 polkavm.Reg, r2 polkavm.Reg) {
	l.log.WithLevel(l.level).Msgf("%d: reverse_bytes %s=0x%x %s=0x%x", l.m.instructionCounter, r1, l.m.regs[r1], r2, l.m.regs[r2])
	l.m.ReverseBytes(r1, r2)
}
func (l *logger) StoreIndirectU8(r1, r2 polkavm.Reg, v1 uint64) error {
	l.log.WithLevel(l.level).Msgf("%d: store_ind_u8 %s=0x%x %s=0x%x v1=0x%x", l.m.instructionCounter, r1, l.m.regs[r1], r2, l.m.regs[r2], v1)
	return l.m.StoreIndirectU8(r1, r2, v1)
}
func (l *logger) StoreIndirectU16(r1, r2 polkavm.Reg, v1 uint64) error {
	l.log.WithLevel(l.level).Msgf("%d: store_ind_u16 %s=0x%x %s=0x%x v1=0x%x", l.m.instructionCounter, r1, l.m.regs[r1], r2, l.m.regs[r2], v1)
	return l.m.StoreIndirectU16(r1, r2, v1)
}
func (l *logger) StoreIndirectU32(r1, r2 polkavm.Reg, v1 uint64) error {
	l.log.WithLevel(l.level).Msgf("%d: store_ind_u32 %s=0x%x %s=0x%x v1=0x%x", l.m.instructionCounter, r1, l.m.regs[r1], r2, l.m.regs[r2], v1)
	return l.m.StoreIndirectU32(r1, r2, v1)
}
func (l *logger) StoreIndirectU64(r1, r2 polkavm.Reg, v1 uint64) error {
	l.log.WithLevel(l.level).Msgf("%d: store_ind_u64 %s=0x%x %s=0x%x v1=0x%x", l.m.instructionCounter, r1, l.m.regs[r1], r2, l.m.regs[r2], v1)
	return l.m.StoreIndirectU64(r1, r2, v1)
}
func (l *logger) LoadIndirectU8(r1, r2 polkavm.Reg, v1 uint64) error {
	l.log.WithLevel(l.level).Msgf("%d: load_ind_u8 %s=0x%x %s=0x%x v1=0x%x", l.m.instructionCounter, r1, l.m.regs[r1], r2, l.m.regs[r2], v1)
	return l.m.LoadIndirectU8(r1, r2, v1)
}
func (l *logger) LoadIndirectI8(r1, r2 polkavm.Reg, v1 uint64) error {
	l.log.WithLevel(l.level).Msgf("%d: load_ind_i8 %s=0x%x %s=0x%x v1=0x%x", l.m.instructionCounter, r1, l.m.regs[r1], r2, l.m.regs[r2], v1)
	return l.m.LoadIndirectI8(r1, r2, v1)
}
func (l *logger) LoadIndirectU16(r1, r2 polkavm.Reg, v1 uint64) error {
	l.log.WithLevel(l.level).Msgf("%d: load_ind_u16 %s=0x%x %s=0x%x v1=0x%x", l.m.instructionCounter, r1, l.m.regs[r1], r2, l.m.regs[r2], v1)
	return l.m.LoadIndirectU16(r1, r2, v1)
}
func (l *logger) LoadIndirectI16(r1, r2 polkavm.Reg, v1 uint64) error {
	l.log.WithLevel(l.level).Msgf("%d: load_ind_i16 %s=0x%x %s=0x%x v1=0x%x", l.m.instructionCounter, r1, l.m.regs[r1], r2, l.m.regs[r2], v1)
	return l.m.LoadIndirectI16(r1, r2, v1)
}
func (l *logger) LoadIndirectU32(r1, r2 polkavm.Reg, v1 uint64) error {
	l.log.WithLevel(l.level).Msgf("%d: load_ind_u32 %s=0x%x %s=0x%x v1=0x%x", l.m.instructionCounter, r1, l.m.regs[r1], r2, l.m.regs[r2], v1)
	return l.m.LoadIndirectU32(r1, r2, v1)
}
func (l *logger) LoadIndirectI32(r1, r2 polkavm.Reg, v1 uint64) error {
	l.log.WithLevel(l.level).Msgf("%d: load_ind_i32 %s=0x%x %s=0x%x v1=0x%x", l.m.instructionCounter, r1, l.m.regs[r1], r2, l.m.regs[r2], v1)
	return l.m.LoadIndirectI32(r1, r2, v1)
}
func (l *logger) LoadIndirectU64(r1, r2 polkavm.Reg, v1 uint64) error {
	l.log.WithLevel(l.level).Msgf("%d: load_ind_u64 %s=0x%x %s=0x%x v1=0x%x", l.m.instructionCounter, r1, l.m.regs[r1], r2, l.m.regs[r2], v1)
	return l.m.LoadIndirectU64(r1, r2, v1)
}
func (l *logger) AddImm32(r1, r2 polkavm.Reg, v1 uint64) {
	l.log.WithLevel(l.level).Msgf("%d: add_imm_32 %s=0x%x %s=0x%x v1=0x%x", l.m.instructionCounter, r1, l.m.regs[r1], r2, l.m.regs[r2], v1)
	l.m.AddImm32(r1, r2, v1)
}
func (l *logger) AndImm(r1, r2 polkavm.Reg, v1 uint64) {
	l.log.WithLevel(l.level).Msgf("%d: and_imm %s=0x%x %s=0x%x v1=0x%x", l.m.instructionCounter, r1, l.m.regs[r1], r2, l.m.regs[r2], v1)
	l.m.AndImm(r1, r2, v1)
}
func (l *logger) XorImm(r1, r2 polkavm.Reg, v1 uint64) {
	l.log.WithLevel(l.level).Msgf("%d: xor_imm %s=0x%x %s=0x%x v1=0x%x", l.m.instructionCounter, r1, l.m.regs[r1], r2, l.m.regs[r2], v1)
	l.m.XorImm(r1, r2, v1)
}
func (l *logger) OrImm(r1, r2 polkavm.Reg, v1 uint64) {
	l.log.WithLevel(l.level).Msgf("%d: or_imm %s=0x%x %s=0x%x v1=0x%x", l.m.instructionCounter, r1, l.m.regs[r1], r2, l.m.regs[r2], v1)
	l.m.OrImm(r1, r2, v1)
}
func (l *logger) MulImm32(r1, r2 polkavm.Reg, v1 uint64) {
	l.log.WithLevel(l.level).Msgf("%d: mul_imm_32 %s=0x%x %s=0x%x v1=0x%x", l.m.instructionCounter, r1, l.m.regs[r1], r2, l.m.regs[r2], v1)
	l.m.MulImm32(r1, r2, v1)
}
func (l *logger) SetLessThanUnsignedImm(r1, r2 polkavm.Reg, v1 uint64) {
	l.log.WithLevel(l.level).Msgf("%d: set_lt_u_imm %s=0x%x %s=0x%x v1=0x%x", l.m.instructionCounter, r1, l.m.regs[r1], r2, l.m.regs[r2], v1)
	l.m.SetLessThanUnsignedImm(r1, r2, v1)
}
func (l *logger) SetLessThanSignedImm(r1, r2 polkavm.Reg, v1 uint64) {
	l.log.WithLevel(l.level).Msgf("%d: set_lt_s_imm %s=0x%x %s=0x%x v1=0x%x", l.m.instructionCounter, r1, l.m.regs[r1], r2, l.m.regs[r2], v1)
	l.m.SetLessThanSignedImm(r1, r2, v1)
}
func (l *logger) ShiftLogicalLeftImm32(r1, r2 polkavm.Reg, v1 uint64) {
	l.log.WithLevel(l.level).Msgf("%d: shlo_l_imm_32 %s=0x%x %s=0x%x v1=0x%x", l.m.instructionCounter, r1, l.m.regs[r1], r2, l.m.regs[r2], v1)
	l.m.ShiftLogicalLeftImm32(r1, r2, v1)
}
func (l *logger) ShiftLogicalRightImm32(r1, r2 polkavm.Reg, v1 uint64) {
	l.log.WithLevel(l.level).Msgf("%d: shlo_r_imm_32 %s=0x%x %s=0x%x v1=0x%x", l.m.instructionCounter, r1, l.m.regs[r1], r2, l.m.regs[r2], v1)
	l.m.ShiftLogicalRightImm32(r1, r2, v1)
}
func (l *logger) ShiftArithmeticRightImm32(r1, r2 polkavm.Reg, v1 uint64) {
	l.log.WithLevel(l.level).Msgf("%d: shar_r_imm_32 %s=0x%x %s=0x%x v1=0x%x", l.m.instructionCounter, r1, l.m.regs[r1], r2, l.m.regs[r2], v1)
	l.m.ShiftArithmeticRightImm32(r1, r2, v1)
}
func (l *logger) NegateAndAddImm32(r1, r2 polkavm.Reg, v1 uint64) {
	l.log.WithLevel(l.level).Msgf("%d: neg_add_imm_32 %s=0x%x %s=0x%x v1=0x%x", l.m.instructionCounter, r1, l.m.regs[r1], r2, l.m.regs[r2], v1)
	l.m.NegateAndAddImm32(r1, r2, v1)
}
func (l *logger) SetGreaterThanUnsignedImm(r1, r2 polkavm.Reg, v1 uint64) {
	l.log.WithLevel(l.level).Msgf("%d: set_gt_u_imm %s=0x%x %s=0x%x v1=0x%x", l.m.instructionCounter, r1, l.m.regs[r1], r2, l.m.regs[r2], v1)
	l.m.SetGreaterThanUnsignedImm(r1, r2, v1)
}
func (l *logger) SetGreaterThanSignedImm(r1, r2 polkavm.Reg, v1 uint64) {
	l.log.WithLevel(l.level).Msgf("%d: set_gt_s_imm %s=0x%x %s=0x%x v1=0x%x", l.m.instructionCounter, r1, l.m.regs[r1], r2, l.m.regs[r2], v1)
	l.m.SetGreaterThanSignedImm(r1, r2, v1)
}
func (l *logger) ShiftLogicalLeftImmAlt32(r1, r2 polkavm.Reg, v1 uint64) {
	l.log.WithLevel(l.level).Msgf("%d: shlo_l_imm_alt_32 %s=0x%x %s=0x%x v1=0x%x", l.m.instructionCounter, r1, l.m.regs[r1], r2, l.m.regs[r2], v1)
	l.m.ShiftLogicalLeftImmAlt32(r1, r2, v1)
}
func (l *logger) ShiftLogicalRightImmAlt32(r1, r2 polkavm.Reg, v1 uint64) {
	l.log.WithLevel(l.level).Msgf("%d: shlo_r_imm_alt_32 %s=0x%x %s=0x%x v1=0x%x", l.m.instructionCounter, r1, l.m.regs[r1], r2, l.m.regs[r2], v1)
	l.m.ShiftLogicalRightImmAlt32(r1, r2, v1)
}
func (l *logger) ShiftArithmeticRightImmAlt32(r1, r2 polkavm.Reg, v1 uint64) {
	l.log.WithLevel(l.level).Msgf("%d: shar_r_imm_alt_32 %s=0x%x %s=0x%x v1=0x%x", l.m.instructionCounter, r1, l.m.regs[r1], r2, l.m.regs[r2], v1)
	l.m.ShiftArithmeticRightImmAlt32(r1, r2, v1)
}
func (l *logger) CmovIfZeroImm(r1, r2 polkavm.Reg, v1 uint64) {
	l.log.WithLevel(l.level).Msgf("%d: cmov_iz_imm %s=0x%x %s=0x%x v1=0x%x", l.m.instructionCounter, r1, l.m.regs[r1], r2, l.m.regs[r2], v1)
	l.m.CmovIfZeroImm(r1, r2, v1)
}
func (l *logger) CmovIfNotZeroImm(r1, r2 polkavm.Reg, v1 uint64) {
	l.log.WithLevel(l.level).Msgf("%d: cmov_nz_imm %s=0x%x %s=0x%x v1=0x%x", l.m.instructionCounter, r1, l.m.regs[r1], r2, l.m.regs[r2], v1)
	l.m.CmovIfNotZeroImm(r1, r2, v1)
}
func (l *logger) AddImm64(r1, r2 polkavm.Reg, v1 uint64) {
	l.log.WithLevel(l.level).Msgf("%d: add_imm_64 %s=0x%x %s=0x%x v1=0x%x", l.m.instructionCounter, r1, l.m.regs[r1], r2, l.m.regs[r2], v1)
	l.m.AddImm64(r1, r2, v1)
}
func (l *logger) MulImm64(r1, r2 polkavm.Reg, v1 uint64) {
	l.log.WithLevel(l.level).Msgf("%d: mul_imm_64 %s=0x%x %s=0x%x v1=0x%x", l.m.instructionCounter, r1, l.m.regs[r1], r2, l.m.regs[r2], v1)
	l.m.MulImm64(r1, r2, v1)
}
func (l *logger) ShiftLogicalLeftImm64(r1, r2 polkavm.Reg, v1 uint64) {
	l.log.WithLevel(l.level).Msgf("%d: shlo_l_imm_64 %s=0x%x %s=0x%x v1=0x%x", l.m.instructionCounter, r1, l.m.regs[r1], r2, l.m.regs[r2], v1)
	l.m.ShiftLogicalLeftImm64(r1, r2, v1)
}
func (l *logger) ShiftLogicalRightImm64(r1, r2 polkavm.Reg, v1 uint64) {
	l.log.WithLevel(l.level).Msgf("%d: shlo_r_imm_64 %s=0x%x %s=0x%x v1=0x%x", l.m.instructionCounter, r1, l.m.regs[r1], r2, l.m.regs[r2], v1)
	l.m.ShiftLogicalRightImm64(r1, r2, v1)
}
func (l *logger) ShiftArithmeticRightImm64(r1, r2 polkavm.Reg, v1 uint64) {
	l.log.WithLevel(l.level).Msgf("%d: shar_r_imm_64 %s=0x%x %s=0x%x v1=0x%x", l.m.instructionCounter, r1, l.m.regs[r1], r2, l.m.regs[r2], v1)
	l.m.ShiftArithmeticRightImm64(r1, r2, v1)
}
func (l *logger) NegateAndAddImm64(r1, r2 polkavm.Reg, v1 uint64) {
	l.log.WithLevel(l.level).Msgf("%d: neg_add_imm_64 %s=0x%x %s=0x%x v1=0x%x", l.m.instructionCounter, r1, l.m.regs[r1], r2, l.m.regs[r2], v1)
	l.m.NegateAndAddImm64(r1, r2, v1)
}
func (l *logger) ShiftLogicalLeftImmAlt64(r1, r2 polkavm.Reg, v1 uint64) {
	l.log.WithLevel(l.level).Msgf("%d: shlo_l_imm_alt_64 %s=0x%x %s=0x%x v1=0x%x", l.m.instructionCounter, r1, l.m.regs[r1], r2, l.m.regs[r2], v1)
	l.m.ShiftLogicalLeftImmAlt64(r1, r2, v1)
}
func (l *logger) ShiftLogicalRightImmAlt64(r1, r2 polkavm.Reg, v1 uint64) {
	l.log.WithLevel(l.level).Msgf("%d: shlo_r_imm_alt_64 %s=0x%x %s=0x%x v1=0x%x", l.m.instructionCounter, r1, l.m.regs[r1], r2, l.m.regs[r2], v1)
	l.m.ShiftLogicalRightImmAlt64(r1, r2, v1)
}
func (l *logger) ShiftArithmeticRightImmAlt64(r1, r2 polkavm.Reg, v1 uint64) {
	l.log.WithLevel(l.level).Msgf("%d: shar_r_imm_alt_64 %s=0x%x %s=0x%x v1=0x%x", l.m.instructionCounter, r1, l.m.regs[r1], r2, l.m.regs[r2], v1)
	l.m.ShiftArithmeticRightImmAlt64(r1, r2, v1)
}
func (l *logger) RotateRight64Imm(r1, r2 polkavm.Reg, v1 uint64) {
	l.log.WithLevel(l.level).Msgf("%d: rot_r_64_imm %s=0x%x %s=0x%x v1=0x%x", l.m.instructionCounter, r1, l.m.regs[r1], r2, l.m.regs[r2], v1)
	l.m.RotateRight64Imm(r1, r2, v1)
}
func (l *logger) RotateRight64ImmAlt(r1, r2 polkavm.Reg, v1 uint64) {
	l.log.WithLevel(l.level).Msgf("%d: rot_r_64_imm_alt %s=0x%x %s=0x%x v1=0x%x", l.m.instructionCounter, r1, l.m.regs[r1], r2, l.m.regs[r2], v1)
	l.m.RotateRight64ImmAlt(r1, r2, v1)
}
func (l *logger) RotateRight32Imm(r1, r2 polkavm.Reg, v1 uint64) {
	l.log.WithLevel(l.level).Msgf("%d: rot_r_32_imm %s=0x%x %s=0x%x v1=0x%x", l.m.instructionCounter, r1, l.m.regs[r1], r2, l.m.regs[r2], v1)
	l.m.RotateRight32Imm(r1, r2, v1)
}
func (l *logger) RotateRight32ImmAlt(r1, r2 polkavm.Reg, v1 uint64) {
	l.log.WithLevel(l.level).Msgf("%d: rot_r_32_imm_alt %s=0x%x %s=0x%x v1=0x%x", l.m.instructionCounter, r1, l.m.regs[r1], r2, l.m.regs[r2], v1)
	l.m.RotateRight32ImmAlt(r1, r2, v1)
}
func (l *logger) BranchEq(r1, r2 polkavm.Reg, v1 uint64) error {
	l.log.WithLevel(l.level).Msgf("%d: branch_eq %s=0x%x %s=0x%x v1=0x%x", l.m.instructionCounter, r1, l.m.regs[r1], r2, l.m.regs[r2], v1)
	return l.m.BranchEq(r1, r2, v1)
}
func (l *logger) BranchNotEq(r1, r2 polkavm.Reg, v1 uint64) error {
	l.log.WithLevel(l.level).Msgf("%d: branch_ne %s=0x%x %s=0x%x v1=0x%x", l.m.instructionCounter, r1, l.m.regs[r1], r2, l.m.regs[r2], v1)
	return l.m.BranchNotEq(r1, r2, v1)
}
func (l *logger) BranchLessUnsigned(r1, r2 polkavm.Reg, v1 uint64) error {
	l.log.WithLevel(l.level).Msgf("%d: branch_lt_u %s=0x%x %s=0x%x v1=0x%x", l.m.instructionCounter, r1, l.m.regs[r1], r2, l.m.regs[r2], v1)
	return l.m.BranchLessUnsigned(r1, r2, v1)
}
func (l *logger) BranchLessSigned(r1, r2 polkavm.Reg, v1 uint64) error {
	l.log.WithLevel(l.level).Msgf("%d: branch_lt_s %s=0x%x %s=0x%x v1=0x%x", l.m.instructionCounter, r1, l.m.regs[r1], r2, l.m.regs[r2], v1)
	return l.m.BranchLessSigned(r1, r2, v1)
}
func (l *logger) BranchGreaterOrEqualUnsigned(r1, r2 polkavm.Reg, v1 uint64) error {
	l.log.WithLevel(l.level).Msgf("%d: branch_ge_u %s=0x%x %s=0x%x v1=0x%x", l.m.instructionCounter, r1, l.m.regs[r1], r2, l.m.regs[r2], v1)
	return l.m.BranchGreaterOrEqualUnsigned(r1, r2, v1)
}
func (l *logger) BranchGreaterOrEqualSigned(r1, r2 polkavm.Reg, v1 uint64) error {
	l.log.WithLevel(l.level).Msgf("%d: branch_ge_s %s=0x%x %s=0x%x v1=0x%x", l.m.instructionCounter, r1, l.m.regs[r1], r2, l.m.regs[r2], v1)
	return l.m.BranchGreaterOrEqualSigned(r1, r2, v1)
}

func (l *logger) LoadImmAndJumpIndirect(r1, r2 polkavm.Reg, v1, v2 uint64) error {
	l.log.WithLevel(l.level).Msgf("%d: load_imm_jump_ind %s=0x%x %s=0x%x v1=0x%x v2=0x%x", l.m.instructionCounter, r1, l.m.regs[r1], r2, l.m.regs[r2], v1, v2)
	return l.m.LoadImmAndJumpIndirect(r1, r2, v1, v2)
}

func (l *logger) Add32(r1, r2, r3 polkavm.Reg) {
	l.log.WithLevel(l.level).Msgf("%d: add_32 %s=0x%x %s=0x%x %s=0x%x", l.m.instructionCounter, r1, l.m.regs[r1], r2, l.m.regs[r2], r3, l.m.regs[r1])
	l.m.Add32(r1, r2, r3)
}
func (l *logger) Sub32(r1, r2, r3 polkavm.Reg) {
	l.log.WithLevel(l.level).Msgf("%d: sub_32 %s=0x%x %s=0x%x %s=0x%x", l.m.instructionCounter, r1, l.m.regs[r1], r2, l.m.regs[r2], r3, l.m.regs[r1])
	l.m.Sub32(r1, r2, r3)
}
func (l *logger) Mul32(r1, r2, r3 polkavm.Reg) {
	l.log.WithLevel(l.level).Msgf("%d: mul_32 %s=0x%x %s=0x%x %s=0x%x", l.m.instructionCounter, r1, l.m.regs[r1], r2, l.m.regs[r2], r3, l.m.regs[r1])
	l.m.Mul32(r1, r2, r3)
}
func (l *logger) DivUnsigned32(r1, r2, r3 polkavm.Reg) {
	l.log.WithLevel(l.level).Msgf("%d: div_u_32 %s=0x%x %s=0x%x %s=0x%x", l.m.instructionCounter, r1, l.m.regs[r1], r2, l.m.regs[r2], r3, l.m.regs[r1])
	l.m.DivUnsigned32(r1, r2, r3)
}
func (l *logger) DivSigned32(r1, r2, r3 polkavm.Reg) {
	l.log.WithLevel(l.level).Msgf("%d: div_s_32 %s=0x%x %s=0x%x %s=0x%x", l.m.instructionCounter, r1, l.m.regs[r1], r2, l.m.regs[r2], r3, l.m.regs[r1])
	l.m.DivSigned32(r1, r2, r3)
}
func (l *logger) RemUnsigned32(r1, r2, r3 polkavm.Reg) {
	l.log.WithLevel(l.level).Msgf("%d: rem_u_32 %s=0x%x %s=0x%x %s=0x%x", l.m.instructionCounter, r1, l.m.regs[r1], r2, l.m.regs[r2], r3, l.m.regs[r1])
	l.m.RemUnsigned32(r1, r2, r3)
}
func (l *logger) RemSigned32(r1, r2, r3 polkavm.Reg) {
	l.log.WithLevel(l.level).Msgf("%d: rem_s_32 %s=0x%x %s=0x%x %s=0x%x", l.m.instructionCounter, r1, l.m.regs[r1], r2, l.m.regs[r2], r3, l.m.regs[r1])
	l.m.RemSigned32(r1, r2, r3)
}
func (l *logger) ShiftLogicalLeft32(r1, r2, r3 polkavm.Reg) {
	l.log.WithLevel(l.level).Msgf("%d: shlo_l_32 %s=0x%x %s=0x%x %s=0x%x", l.m.instructionCounter, r1, l.m.regs[r1], r2, l.m.regs[r2], r3, l.m.regs[r1])
	l.m.ShiftLogicalLeft32(r1, r2, r3)
}
func (l *logger) ShiftLogicalRight32(r1, r2, r3 polkavm.Reg) {
	l.log.WithLevel(l.level).Msgf("%d: shlo_r_32 %s=0x%x %s=0x%x %s=0x%x", l.m.instructionCounter, r1, l.m.regs[r1], r2, l.m.regs[r2], r3, l.m.regs[r1])
	l.m.ShiftLogicalRight32(r1, r2, r3)
}
func (l *logger) ShiftArithmeticRight32(r1, r2, r3 polkavm.Reg) {
	l.log.WithLevel(l.level).Msgf("%d: shar_r_32 %s=0x%x %s=0x%x %s=0x%x", l.m.instructionCounter, r1, l.m.regs[r1], r2, l.m.regs[r2], r3, l.m.regs[r1])
	l.m.ShiftArithmeticRight32(r1, r2, r3)
}
func (l *logger) Add64(r1, r2, r3 polkavm.Reg) {
	l.log.WithLevel(l.level).Msgf("%d: add_64 %s=0x%x %s=0x%x %s=0x%x", l.m.instructionCounter, r1, l.m.regs[r1], r2, l.m.regs[r2], r3, l.m.regs[r1])
	l.m.Add64(r1, r2, r3)
}
func (l *logger) Sub64(r1, r2, r3 polkavm.Reg) {
	l.log.WithLevel(l.level).Msgf("%d: sub_64 %s=0x%x %s=0x%x %s=0x%x", l.m.instructionCounter, r1, l.m.regs[r1], r2, l.m.regs[r2], r3, l.m.regs[r1])
	l.m.Sub64(r1, r2, r3)
}
func (l *logger) Mul64(r1, r2, r3 polkavm.Reg) {
	l.log.WithLevel(l.level).Msgf("%d: mul_64 %s=0x%x %s=0x%x %s=0x%x", l.m.instructionCounter, r1, l.m.regs[r1], r2, l.m.regs[r2], r3, l.m.regs[r1])
	l.m.Mul64(r1, r2, r3)
}
func (l *logger) DivUnsigned64(r1, r2, r3 polkavm.Reg) {
	l.log.WithLevel(l.level).Msgf("%d: div_u_64 %s=0x%x %s=0x%x %s=0x%x", l.m.instructionCounter, r1, l.m.regs[r1], r2, l.m.regs[r2], r3, l.m.regs[r1])
	l.m.DivUnsigned64(r1, r2, r3)
}
func (l *logger) DivSigned64(r1, r2, r3 polkavm.Reg) {
	l.log.WithLevel(l.level).Msgf("%d: div_s_64 %s=0x%x %s=0x%x %s=0x%x", l.m.instructionCounter, r1, l.m.regs[r1], r2, l.m.regs[r2], r3, l.m.regs[r1])
	l.m.DivSigned64(r1, r2, r3)
}
func (l *logger) RemUnsigned64(r1, r2, r3 polkavm.Reg) {
	l.log.WithLevel(l.level).Msgf("%d: rem_u_64 %s=0x%x %s=0x%x %s=0x%x", l.m.instructionCounter, r1, l.m.regs[r1], r2, l.m.regs[r2], r3, l.m.regs[r1])
	l.m.RemUnsigned64(r1, r2, r3)
}
func (l *logger) RemSigned64(r1, r2, r3 polkavm.Reg) {
	l.log.WithLevel(l.level).Msgf("%d: rem_s_64 %s=0x%x %s=0x%x %s=0x%x", l.m.instructionCounter, r1, l.m.regs[r1], r2, l.m.regs[r2], r3, l.m.regs[r1])
	l.m.RemSigned64(r1, r2, r3)
}
func (l *logger) ShiftLogicalLeft64(r1, r2, r3 polkavm.Reg) {
	l.log.WithLevel(l.level).Msgf("%d: shlo_l_64 %s=0x%x %s=0x%x %s=0x%x", l.m.instructionCounter, r1, l.m.regs[r1], r2, l.m.regs[r2], r3, l.m.regs[r1])
	l.m.ShiftLogicalLeft64(r1, r2, r3)
}
func (l *logger) ShiftLogicalRight64(r1, r2, r3 polkavm.Reg) {
	l.log.WithLevel(l.level).Msgf("%d: shlo_r_64 %s=0x%x %s=0x%x %s=0x%x", l.m.instructionCounter, r1, l.m.regs[r1], r2, l.m.regs[r2], r3, l.m.regs[r1])
	l.m.ShiftLogicalRight64(r1, r2, r3)
}
func (l *logger) ShiftArithmeticRight64(r1, r2, r3 polkavm.Reg) {
	l.log.WithLevel(l.level).Msgf("%d: shar_r_64 %s=0x%x %s=0x%x %s=0x%x", l.m.instructionCounter, r1, l.m.regs[r1], r2, l.m.regs[r2], r3, l.m.regs[r1])
	l.m.ShiftArithmeticRight64(r1, r2, r3)
}
func (l *logger) And(r1, r2, r3 polkavm.Reg) {
	l.log.WithLevel(l.level).Msgf("%d: and %s=0x%x %s=0x%x %s=0x%x", l.m.instructionCounter, r1, l.m.regs[r1], r2, l.m.regs[r2], r3, l.m.regs[r1])
	l.m.And(r1, r2, r3)
}
func (l *logger) Xor(r1, r2, r3 polkavm.Reg) {
	l.log.WithLevel(l.level).Msgf("%d: xor %s=0x%x %s=0x%x %s=0x%x", l.m.instructionCounter, r1, l.m.regs[r1], r2, l.m.regs[r2], r3, l.m.regs[r1])
	l.m.Xor(r1, r2, r3)
}
func (l *logger) Or(r1, r2, r3 polkavm.Reg) {
	l.log.WithLevel(l.level).Msgf("%d: or %s=0x%x %s=0x%x %s=0x%x", l.m.instructionCounter, r1, l.m.regs[r1], r2, l.m.regs[r2], r3, l.m.regs[r1])
	l.m.Or(r1, r2, r3)
}
func (l *logger) MulUpperSignedSigned(r1, r2, r3 polkavm.Reg) {
	l.log.WithLevel(l.level).Msgf("%d: mul_upper_s_s %s=0x%x %s=0x%x %s=0x%x", l.m.instructionCounter, r1, l.m.regs[r1], r2, l.m.regs[r2], r3, l.m.regs[r1])
	l.m.MulUpperSignedSigned(r1, r2, r3)
}
func (l *logger) MulUpperUnsignedUnsigned(r1, r2, r3 polkavm.Reg) {
	l.log.WithLevel(l.level).Msgf("%d: mul_upper_u_u %s=0x%x %s=0x%x %s=0x%x", l.m.instructionCounter, r1, l.m.regs[r1], r2, l.m.regs[r2], r3, l.m.regs[r1])
	l.m.MulUpperUnsignedUnsigned(r1, r2, r3)
}
func (l *logger) MulUpperSignedUnsigned(r1, r2, r3 polkavm.Reg) {
	l.log.WithLevel(l.level).Msgf("%d: mul_upper_s_u %s=0x%x %s=0x%x %s=0x%x", l.m.instructionCounter, r1, l.m.regs[r1], r2, l.m.regs[r2], r3, l.m.regs[r1])
	l.m.MulUpperSignedUnsigned(r1, r2, r3)
}
func (l *logger) SetLessThanUnsigned(r1, r2, r3 polkavm.Reg) {
	l.log.WithLevel(l.level).Msgf("%d: set_lt_u %s=0x%x %s=0x%x %s=0x%x", l.m.instructionCounter, r1, l.m.regs[r1], r2, l.m.regs[r2], r3, l.m.regs[r1])
	l.m.SetLessThanUnsigned(r1, r2, r3)
}
func (l *logger) SetLessThanSigned(r1, r2, r3 polkavm.Reg) {
	l.log.WithLevel(l.level).Msgf("%d: set_lt_s %s=0x%x %s=0x%x %s=0x%x", l.m.instructionCounter, r1, l.m.regs[r1], r2, l.m.regs[r2], r3, l.m.regs[r1])
	l.m.SetLessThanSigned(r1, r2, r3)
}
func (l *logger) CmovIfZero(r1, r2, r3 polkavm.Reg) {
	l.log.WithLevel(l.level).Msgf("%d: cmov_iz %s=0x%x %s=0x%x %s=0x%x", l.m.instructionCounter, r1, l.m.regs[r1], r2, l.m.regs[r2], r3, l.m.regs[r1])
	l.m.CmovIfZero(r1, r2, r3)
}
func (l *logger) CmovIfNotZero(r1, r2, r3 polkavm.Reg) {
	l.log.WithLevel(l.level).Msgf("%d: cmov_nz %s=0x%x %s=0x%x %s=0x%x", l.m.instructionCounter, r1, l.m.regs[r1], r2, l.m.regs[r2], r3, l.m.regs[r1])
	l.m.CmovIfNotZero(r1, r2, r3)
}
func (l *logger) RotateLeft64(r1, r2, r3 polkavm.Reg) {
	l.log.WithLevel(l.level).Msgf("%d: rot_l_64 %s=0x%x %s=0x%x %s=0x%x", l.m.instructionCounter, r1, l.m.regs[r1], r2, l.m.regs[r2], r3, l.m.regs[r1])
	l.m.RotateLeft64(r1, r2, r3)
}
func (l *logger) RotateLeft32(r1, r2, r3 polkavm.Reg) {
	l.log.WithLevel(l.level).Msgf("%d: rot_l_32 %s=0x%x %s=0x%x %s=0x%x", l.m.instructionCounter, r1, l.m.regs[r1], r2, l.m.regs[r2], r3, l.m.regs[r1])
	l.m.RotateLeft32(r1, r2, r3)
}
func (l *logger) RotateRight64(r1, r2, r3 polkavm.Reg) {
	l.log.WithLevel(l.level).Msgf("%d: rot_r_64 %s=0x%x %s=0x%x %s=0x%x", l.m.instructionCounter, r1, l.m.regs[r1], r2, l.m.regs[r2], r3, l.m.regs[r1])
	l.m.RotateRight64(r1, r2, r3)
}
func (l *logger) RotateRight32(r1, r2, r3 polkavm.Reg) {
	l.log.WithLevel(l.level).Msgf("%d: rot_r_32 %s=0x%x %s=0x%x %s=0x%x", l.m.instructionCounter, r1, l.m.regs[r1], r2, l.m.regs[r2], r3, l.m.regs[r1])
	l.m.RotateRight32(r1, r2, r3)
}
func (l *logger) AndInverted(r1, r2, r3 polkavm.Reg) {
	l.log.WithLevel(l.level).Msgf("%d: and_inv %s=0x%x %s=0x%x %s=0x%x", l.m.instructionCounter, r1, l.m.regs[r1], r2, l.m.regs[r2], r3, l.m.regs[r1])
	l.m.AndInverted(r1, r2, r3)
}
func (l *logger) OrInverted(r1, r2, r3 polkavm.Reg) {
	l.log.WithLevel(l.level).Msgf("%d: or_inv %s=0x%x %s=0x%x %s=0x%x", l.m.instructionCounter, r1, l.m.regs[r1], r2, l.m.regs[r2], r3, l.m.regs[r1])
	l.m.OrInverted(r1, r2, r3)
}
func (l *logger) Xnor(r1, r2, r3 polkavm.Reg) {
	l.log.WithLevel(l.level).Msgf("%d: xnor %s=0x%x %s=0x%x %s=0x%x", l.m.instructionCounter, r1, l.m.regs[r1], r2, l.m.regs[r2], r3, l.m.regs[r1])
	l.m.Xnor(r1, r2, r3)
}
func (l *logger) Max(r1, r2, r3 polkavm.Reg) {
	l.log.WithLevel(l.level).Msgf("%d: max %s=0x%x %s=0x%x %s=0x%x", l.m.instructionCounter, r1, l.m.regs[r1], r2, l.m.regs[r2], r3, l.m.regs[r1])
	l.m.Max(r1, r2, r3)
}
func (l *logger) MaxUnsigned(r1, r2, r3 polkavm.Reg) {
	l.log.WithLevel(l.level).Msgf("%d: max_u %s=0x%x %s=0x%x %s=0x%x", l.m.instructionCounter, r1, l.m.regs[r1], r2, l.m.regs[r2], r3, l.m.regs[r1])
	l.m.MaxUnsigned(r1, r2, r3)
}
func (l *logger) Min(r1, r2, r3 polkavm.Reg) {
	l.log.WithLevel(l.level).Msgf("%d: min %s=0x%x %s=0x%x %s=0x%x", l.m.instructionCounter, r1, l.m.regs[r1], r2, l.m.regs[r2], r3, l.m.regs[r1])
	l.m.Min(r1, r2, r3)
}
func (l *logger) MinUnsigned(r1, r2, r3 polkavm.Reg) {
	l.log.WithLevel(l.level).Msgf("%d: min_u %s=0x%x %s=0x%x %s=0x%x", l.m.instructionCounter, r1, l.m.regs[r1], r2, l.m.regs[r2], r3, l.m.regs[r1])
	l.m.MinUnsigned(r1, r2, r3)
}
