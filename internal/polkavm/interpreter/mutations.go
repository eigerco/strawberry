package interpreter

import (
	"math"
	"math/big"
	"math/bits"

	"github.com/eigerco/strawberry/internal/polkavm"
	"github.com/eigerco/strawberry/pkg/log"
)

// Trap trap ε = ☇
func (i *Instance) Trap() error {
	log.VM.Trace().Int64("gas", i.gasRemaining).Msgf("%d: trap", i.instructionCounter)
	return polkavm.ErrPanicf("explicit trap")
}

// Fallthrough fallthrough
func (i *Instance) Fallthrough() {
	log.VM.Trace().Int64("gas", i.gasRemaining).Msgf("%d: fallthrough", i.instructionCounter)
	i.skip()
}

// LoadImm64 load_imm_64 φ′A = νX
func (i *Instance) LoadImm64(dst polkavm.Reg, imm uint64) {
	log.VM.Trace().Int64("gas", i.gasRemaining).Msgf("%d: load_imm_64 %s=0x%x v1=0x%x", i.instructionCounter, dst, i.regs[dst], imm)
	i.setAndSkip(dst, imm)
}

// StoreImmU8 store_imm_u8 μ′↺νX = νY mod 28
func (i *Instance) StoreImmU8(address uint64, value uint64) error {
	log.VM.Trace().Int64("gas", i.gasRemaining).Msgf("%d: store_imm_u8 v1=0x%x v2=0x%x", i.instructionCounter, address, value)
	return i.store(address, uint8(value))
}

// StoreImmU16 store_imm_u16 μ′↺{νX...+2} = E2(νY mod 2^16)
func (i *Instance) StoreImmU16(address uint64, value uint64) error {
	log.VM.Trace().Int64("gas", i.gasRemaining).Msgf("%d: store_imm_u16 v1=0x%x v2=0x%x", i.instructionCounter, address, value)
	return i.store(address, uint16(value))
}

// StoreImmU32 store_imm_u32 μ′↺{νX...+4} = E4(νY mod 2^32)
func (i *Instance) StoreImmU32(address uint64, value uint64) error {
	log.VM.Trace().Int64("gas", i.gasRemaining).Msgf("%d: store_imm_u32 v1=0x%x v2=0x%x", i.instructionCounter, address, value)
	return i.store(address, uint32(value))
}

// StoreImmU64 store_imm_u64 μ′↺{νX...+8} = E8(νY)
func (i *Instance) StoreImmU64(address uint64, value uint64) error {
	log.VM.Trace().Int64("gas", i.gasRemaining).Msgf("%d: store_imm_u64 v1=0x%x v2=0x%x", i.instructionCounter, address, value)
	return i.store(address, value)
}

// Jump jump branch(νX , ⊺)
func (i *Instance) Jump(target uint64) error {
	log.VM.Trace().Int64("gas", i.gasRemaining).Msgf("%d: jump v1=0x%x", i.instructionCounter, target)
	return i.branch(true, target)
}

// JumpIndirect jump_ind djump((φA + νX) mod 2^32)
func (i *Instance) JumpIndirect(base polkavm.Reg, offset uint64) error {
	log.VM.Trace().Int64("gas", i.gasRemaining).Msgf("%d: jump_ind %s=0x%x v1=0x%x", i.instructionCounter, base, i.regs[base], offset)
	return i.djump(i.regs[base] + offset)
}

// LoadImm load_imm φ′A = νX
func (i *Instance) LoadImm(dst polkavm.Reg, imm uint64) {
	log.VM.Trace().Int64("gas", i.gasRemaining).Msgf("%d: load_imm %s=0x%x v1=0x%x", i.instructionCounter, dst, i.regs[dst], imm)
	i.setAndSkip(dst, imm)
}

// LoadU8 load_u8 φ′A = μ↺_νX
func (i *Instance) LoadU8(dst polkavm.Reg, address uint64) error {
	log.VM.Trace().Int64("gas", i.gasRemaining).Msgf("%d: load_u8 %s=0x%x v1=0x%x", i.instructionCounter, dst, i.regs[dst], address)
	slice := make([]byte, 1)
	if err := i.memory.Read(address, slice); err != nil {
		return err
	}
	i.setAndSkip(dst, uint64(slice[0]))
	return nil
}

// LoadI8 load_i8 φ′A = X1(μ↺_νX)
func (i *Instance) LoadI8(dst polkavm.Reg, address uint64) error {
	log.VM.Trace().Int64("gas", i.gasRemaining).Msgf("%d: load_i8 %s=0x%x v1=0x%x", i.instructionCounter, dst, i.regs[dst], address)
	slice := make([]byte, 1)
	if err := i.memory.Read(address, slice); err != nil {
		return err
	}
	i.setAndSkip(dst, uint64(int8(slice[0])))
	return nil
}

// LoadU16 load_u16 φ′A = E−1_2 (μ↺_{νX...+2})
func (i *Instance) LoadU16(dst polkavm.Reg, address uint64) error {
	log.VM.Trace().Int64("gas", i.gasRemaining).Msgf("%d: load_u16 %s=0x%x v1=0x%x", i.instructionCounter, dst, i.regs[dst], address)
	var v uint16
	if err := i.load(address, 2, &v); err != nil {
		return err
	}
	i.setAndSkip(dst, uint64(v))
	return nil
}

// LoadI16 load_i16 φ′A = X2(E−1_2 (μ↺_{νX...+2})
func (i *Instance) LoadI16(dst polkavm.Reg, address uint64) error {
	log.VM.Trace().Int64("gas", i.gasRemaining).Msgf("%d: load_i16 %s=0x%x v1=0x%x", i.instructionCounter, dst, i.regs[dst], address)
	var v int16
	if err := i.load(address, 2, &v); err != nil {
		return err
	}
	i.setAndSkip(dst, uint64(v))
	return nil
}

// LoadU32 load_u32 φ′A = E−1_4 (μ↺_{νX...+4})
func (i *Instance) LoadU32(dst polkavm.Reg, address uint64) error {
	log.VM.Trace().Int64("gas", i.gasRemaining).Msgf("%d: load_u32 %s=0x%x v1=0x%x", i.instructionCounter, dst, i.regs[dst], address)
	var v uint32
	if err := i.load(address, 4, &v); err != nil {
		return err
	}
	i.setAndSkip(dst, uint64(v))
	return nil
}

// LoadI32 load_i32 φ′A = X4(E−1_4(μ↺_{νX...+4}))
func (i *Instance) LoadI32(dst polkavm.Reg, address uint64) error {
	log.VM.Trace().Int64("gas", i.gasRemaining).Msgf("%d: load_i32 %s=0x%x v1=0x%x", i.instructionCounter, dst, i.regs[dst], address)
	var v uint32
	if err := i.load(address, 4, &v); err != nil {
		return err
	}
	i.setAndSkip(dst, sext(uint64(v), 4))
	return nil
}

// LoadU64 load_u64 φ′A = E−1_8 (μ↺_{νX...+8})
func (i *Instance) LoadU64(dst polkavm.Reg, address uint64) error {
	log.VM.Trace().Int64("gas", i.gasRemaining).Msgf("%d: load_u64 %s=0x%x v1=0x%x", i.instructionCounter, dst, i.regs[dst], address)
	var v uint64
	if err := i.load(address, 8, &v); err != nil {
		return err
	}
	i.setAndSkip(dst, v)
	return nil
}

// StoreU8 store_u8 μ′↺_νX = φA mod 2^8
func (i *Instance) StoreU8(src polkavm.Reg, address uint64) error {
	log.VM.Trace().Int64("gas", i.gasRemaining).Msgf("%d: store_u8 %s=0x%x v1=0x%x", i.instructionCounter, src, i.regs[src], address)
	return i.store(address, uint8(i.regs[src]))
}

// StoreU16 store_u16 μ′↺_{νX...+2} = E2(φA mod 2^16)
func (i *Instance) StoreU16(src polkavm.Reg, address uint64) error {
	log.VM.Trace().Int64("gas", i.gasRemaining).Msgf("%d: store_u16 %s=0x%x v1=0x%x", i.instructionCounter, src, i.regs[src], address)
	return i.store(address, uint16(i.regs[src]))
}

// StoreU32 store_u32 μ′↺_{νX...+4} = E4(φA mod 2^32)
func (i *Instance) StoreU32(src polkavm.Reg, address uint64) error {
	log.VM.Trace().Int64("gas", i.gasRemaining).Msgf("%d: store_u32 %s=0x%x v1=0x%x", i.instructionCounter, src, i.regs[src], address)
	return i.store(address, uint32(i.regs[src]))
}

// StoreU64 store_u64 μ′↺_{νX...+8} = E8(φA)
func (i *Instance) StoreU64(src polkavm.Reg, address uint64) error {
	log.VM.Trace().Int64("gas", i.gasRemaining).Msgf("%d: store_u64 %s=0x%x v1=0x%x", i.instructionCounter, src, i.regs[src], address)
	return i.store(address, i.regs[src])
}

// StoreImmIndirectU8 store_imm_ind_u8 μ′↺_{φA+νX} = νY mod 2^8
func (i *Instance) StoreImmIndirectU8(base polkavm.Reg, offset uint64, value uint64) error {
	log.VM.Trace().Int64("gas", i.gasRemaining).Msgf("%d: store_imm_ind_u8 %s=0x%x v1=0x%x v2=0x%x", i.instructionCounter, base, i.regs[base], offset, value)
	return i.store(i.regs[base]+offset, uint8(value))
}

// StoreImmIndirectU16 store_imm_ind_u16 μ′↺_{φA+νX...+2} = E2(νY mod 2^16)
func (i *Instance) StoreImmIndirectU16(base polkavm.Reg, offset uint64, value uint64) error {
	log.VM.Trace().Int64("gas", i.gasRemaining).Msgf("%d: store_imm_ind_u16 %s=0x%x v1=0x%x v2=0x%x", i.instructionCounter, base, i.regs[base], offset, value)
	return i.store(i.regs[base]+offset, uint16(value))
}

// StoreImmIndirectU32 store_imm_ind_u32 μ′↺_{φA+νX...+4} = E4(νY mod 2^32)
func (i *Instance) StoreImmIndirectU32(base polkavm.Reg, offset uint64, value uint64) error {
	log.VM.Trace().Int64("gas", i.gasRemaining).Msgf("%d: store_imm_ind_u32 %s=0x%x v1=0x%x v2=0x%x", i.instructionCounter, base, i.regs[base], offset, value)
	return i.store(i.regs[base]+offset, uint32(value))
}

// StoreImmIndirectU64 store_imm_ind_u64 μ′↺_{φA+νX...+8} = E8(νY)
func (i *Instance) StoreImmIndirectU64(base polkavm.Reg, offset uint64, value uint64) error {
	log.VM.Trace().Int64("gas", i.gasRemaining).Msgf("%d: store_imm_ind_u64 %s=0x%x v1=0x%x v2=0x%x", i.instructionCounter, base, i.regs[base], offset, value)
	return i.store(i.regs[base]+offset, value)
}

// LoadImmAndJump load_imm_jump branch(νY , ⊺), φ′A = νX
func (i *Instance) LoadImmAndJump(ra polkavm.Reg, value uint64, target uint64) error {
	log.VM.Trace().Int64("gas", i.gasRemaining).Msgf("%d: load_imm_jump %s=0x%x v1=0x%x v2=0x%x", i.instructionCounter, ra, i.regs[ra], value, target)
	i.regs[ra] = value
	return i.branch(true, target)
}

// BranchEqImm branch_eq_imm branch(νY, φA = νX)
func (i *Instance) BranchEqImm(regA polkavm.Reg, valueX uint64, target uint64) error {
	log.VM.Trace().Int64("gas", i.gasRemaining).Msgf("%d: branch_eq_imm %s=0x%x v1=0x%x v2=0x%x", i.instructionCounter, regA, i.regs[regA], valueX, target)
	return i.branch(i.regs[regA] == valueX, target)
}

// BranchNotEqImm branch_ne_imm branch(νY, φA ≠ νX)
func (i *Instance) BranchNotEqImm(regA polkavm.Reg, valueX uint64, target uint64) error {
	log.VM.Trace().Int64("gas", i.gasRemaining).Msgf("%d: branch_ne_imm %s=0x%x v1=0x%x v2=0x%x", i.instructionCounter, regA, i.regs[regA], valueX, target)
	return i.branch(i.regs[regA] != valueX, target)
}

// BranchLessUnsignedImm branch_lt_u_imm branch(νY , φA < νX)
func (i *Instance) BranchLessUnsignedImm(regA polkavm.Reg, valueX uint64, target uint64) error {
	log.VM.Trace().Int64("gas", i.gasRemaining).Msgf("%d: branch_lt_u_imm %s=0x%x v1=0x%x v2=0x%x", i.instructionCounter, regA, i.regs[regA], valueX, target)
	return i.branch(i.regs[regA] < valueX, target)
}

// BranchLessOrEqualUnsignedImm branch_le_u_imm branch(νY, φA ≤ νX)
func (i *Instance) BranchLessOrEqualUnsignedImm(regA polkavm.Reg, valueX uint64, target uint64) error {
	log.VM.Trace().Int64("gas", i.gasRemaining).Msgf("%d: branch_le_u_imm %s=0x%x v1=0x%x v2=0x%x", i.instructionCounter, regA, i.regs[regA], valueX, target)
	return i.branch(i.regs[regA] <= valueX, target)
}

// BranchGreaterOrEqualUnsignedImm branch_ge_u_imm branch(νY, φA ≥ νX)
func (i *Instance) BranchGreaterOrEqualUnsignedImm(regA polkavm.Reg, valueX uint64, target uint64) error {
	log.VM.Trace().Int64("gas", i.gasRemaining).Msgf("%d: branch_ge_u_imm %s=0x%x v1=0x%x v2=0x%x", i.instructionCounter, regA, i.regs[regA], valueX, target)
	return i.branch(i.regs[regA] >= valueX, target)
}

// BranchGreaterUnsignedImm branch_gt_u_imm branch(νY, φA > νX)
func (i *Instance) BranchGreaterUnsignedImm(regA polkavm.Reg, valueX uint64, target uint64) error {
	log.VM.Trace().Int64("gas", i.gasRemaining).Msgf("%d: branch_gt_u_imm %s=0x%x v1=0x%x v2=0x%x", i.instructionCounter, regA, i.regs[regA], valueX, target)
	return i.branch(i.regs[regA] > valueX, target)
}

// BranchLessSignedImm branch_lt_s_imm branch(νY, Z8(φA) < Z8(νX))
func (i *Instance) BranchLessSignedImm(regA polkavm.Reg, valueX uint64, target uint64) error {
	log.VM.Trace().Int64("gas", i.gasRemaining).Msgf("%d: branch_lt_s_imm %s=0x%x v1=0x%x v2=0x%x", i.instructionCounter, regA, i.regs[regA], valueX, target)
	return i.branch(int64(i.regs[regA]) < int64(valueX), target)
}

// BranchLessOrEqualSignedImm branch_le_s_imm branch(νY , Z8(φA) ≤ Z8(νX))
func (i *Instance) BranchLessOrEqualSignedImm(regA polkavm.Reg, valueX uint64, target uint64) error {
	log.VM.Trace().Int64("gas", i.gasRemaining).Msgf("%d: branch_le_s_imm %s=0x%x v1=0x%x v2=0x%x", i.instructionCounter, regA, i.regs[regA], valueX, target)
	return i.branch(int64(i.regs[regA]) <= int64(valueX), target)
}

// BranchGreaterOrEqualSignedImm branch_ge_s_imm branch(νY, Z8(φA) ≥ Z8(νX))
func (i *Instance) BranchGreaterOrEqualSignedImm(regA polkavm.Reg, valueX uint64, target uint64) error {
	log.VM.Trace().Int64("gas", i.gasRemaining).Msgf("%d: branch_ge_s_imm %s=0x%x v1=0x%x v2=0x%x", i.instructionCounter, regA, i.regs[regA], valueX, target)
	return i.branch(int64(i.regs[regA]) >= int64(valueX), target)
}

// BranchGreaterSignedImm branch_gt_s_imm branch(νY, Z8(φA) > Z8(νX))
func (i *Instance) BranchGreaterSignedImm(regA polkavm.Reg, valueX uint64, target uint64) error {
	log.VM.Trace().Int64("gas", i.gasRemaining).Msgf("%d: branch_gt_s_imm %s=0x%x v1=0x%x v2=0x%x", i.instructionCounter, regA, i.regs[regA], valueX, target)
	return i.branch(int64(i.regs[regA]) > int64(valueX), target)
}

// MoveReg move_reg φ′D = φA
func (i *Instance) MoveReg(dst polkavm.Reg, s polkavm.Reg) {
	log.VM.Trace().Int64("gas", i.gasRemaining).Msgf("%d: move_reg %s=0x%x %s=0x%x", i.instructionCounter, dst, i.regs[dst], s, i.regs[s])
	i.setAndSkip(dst, i.regs[s])
}

// Sbrk sbrk φ′D ≡ min(x ∈ NR) ∶
// x ≥ h
// Nx⋅⋅⋅+φA ~⊆ Vμ
// Nx⋅⋅⋅+φA ⊆ V∗μ′
// The term h above refers to the beginning of the heap
func (i *Instance) Sbrk(dst polkavm.Reg, sizeReg polkavm.Reg) error {
	log.VM.Trace().Int64("gas", i.gasRemaining).Msgf("%d: sbrk %s=0x%x %s=0x%x", i.instructionCounter, dst, i.regs[dst], sizeReg, i.regs[sizeReg])
	size := i.regs[sizeReg]
	heapTop, err := i.memory.Sbrk(size)
	if err != nil {
		return err
	}
	i.setAndSkip(dst, heapTop)
	return nil
}

// CountSetBits64 count_set_bits_64 φ′D = {63;i=0}∑ B8(φA)_i
func (i *Instance) CountSetBits64(dst polkavm.Reg, s polkavm.Reg) {
	log.VM.Trace().Int64("gas", i.gasRemaining).Msgf("%d: count_set_bits_64 %s=0x%x %s=0x%x", i.instructionCounter, dst, i.regs[dst], s, i.regs[s])
	i.setAndSkip(dst, uint64(bits.OnesCount64(i.regs[s])))
}

// CountSetBits32 count_set_bits_32 φ′D = {31;i=0}∑ B4(φA mod 2^32)_i
func (i *Instance) CountSetBits32(dst polkavm.Reg, s polkavm.Reg) {
	log.VM.Trace().Int64("gas", i.gasRemaining).Msgf("%d: count_set_bits_32 %s=0x%x %s=0x%x", i.instructionCounter, dst, i.regs[dst], s, i.regs[s])
	i.setAndSkip(dst, uint64(bits.OnesCount32(uint32(i.regs[s]))))
}

// LeadingZeroBits64 leading_zero_bits_64 φ′D = max(n ∈ N65) where {i<n;i=0}∑ ←B8(φA)_i = 0
func (i *Instance) LeadingZeroBits64(dst polkavm.Reg, s polkavm.Reg) {
	log.VM.Trace().Int64("gas", i.gasRemaining).Msgf("%d: leading_zero_bits_64 %s=0x%x %s=0x%x", i.instructionCounter, dst, i.regs[dst], s, i.regs[s])
	i.setAndSkip(dst, uint64(bits.LeadingZeros64(i.regs[s])))
}

// LeadingZeroBits32 leading_zero_bits_32 φ′D = max(n ∈ N33) where {i<n;i=0}∑ ←B4(φA mod 232)_i = 0
func (i *Instance) LeadingZeroBits32(dst polkavm.Reg, s polkavm.Reg) {
	log.VM.Trace().Int64("gas", i.gasRemaining).Msgf("%d: leading_zero_bits_32 %s=0x%x %s=0x%x", i.instructionCounter, dst, i.regs[dst], s, i.regs[s])
	i.setAndSkip(dst, uint64(bits.LeadingZeros32(uint32(i.regs[s]))))
}

// TrailingZeroBits64 trailing_zero_bits_64 φ′D = max(n ∈ N65) where {i<n;i=0}∑ B8(φA)_i = 0
func (i *Instance) TrailingZeroBits64(dst polkavm.Reg, s polkavm.Reg) {
	log.VM.Trace().Int64("gas", i.gasRemaining).Msgf("%d: trailing_zero_bits_64 %s=0x%x %s=0x%x", i.instructionCounter, dst, i.regs[dst], s, i.regs[s])
	i.setAndSkip(dst, uint64(bits.TrailingZeros64(i.regs[s])))
}

// TrailingZeroBits32 trailing_zero_bits_32 φ′D = max(n ∈ N33) where {i<n;i=0}∑ B4(φA mod 232)_i = 0
func (i *Instance) TrailingZeroBits32(dst polkavm.Reg, s polkavm.Reg) {
	log.VM.Trace().Int64("gas", i.gasRemaining).Msgf("%d: trailing_zero_bits_32 %s=0x%x %s=0x%x", i.instructionCounter, dst, i.regs[dst], s, i.regs[s])
	i.setAndSkip(dst, uint64(bits.TrailingZeros32(uint32(i.regs[s]))))
}

// SignExtend8 sign_extend_8 φ′D = Z−1_8(Z_1(φA mod 2^8))
func (i *Instance) SignExtend8(dst polkavm.Reg, s polkavm.Reg) {
	log.VM.Trace().Int64("gas", i.gasRemaining).Msgf("%d: sign_extend_8 %s=0x%x %s=0x%x", i.instructionCounter, dst, i.regs[dst], s, i.regs[s])
	i.setAndSkip(dst, uint64(int8(uint8(i.regs[s]))))
}

// SignExtend16 sign_extend_16 φ′D = Z−1_8(Z_2(φA mod 2^16))
func (i *Instance) SignExtend16(dst polkavm.Reg, s polkavm.Reg) {
	log.VM.Trace().Int64("gas", i.gasRemaining).Msgf("%d: sign_extend_16 %s=0x%x %s=0x%x", i.instructionCounter, dst, i.regs[dst], s, i.regs[s])
	i.setAndSkip(dst, uint64(int16(uint16(i.regs[s]))))
}

// ZeroExtend16 zero_extend_16 φ′D = φA mod 2^16
func (i *Instance) ZeroExtend16(dst polkavm.Reg, s polkavm.Reg) {
	log.VM.Trace().Int64("gas", i.gasRemaining).Msgf("%d: zero_extend_16 %s=0x%x %s=0x%x", i.instructionCounter, dst, i.regs[dst], s, i.regs[s])
	i.setAndSkip(dst, uint64(uint16(i.regs[s])))
}

// ReverseBytes reverse_bytes ∀i ∈ N8 ∶ E8(φ′D)i = E8(φA)_7−i
func (i *Instance) ReverseBytes(dst polkavm.Reg, s polkavm.Reg) {
	log.VM.Trace().Int64("gas", i.gasRemaining).Msgf("%d: reverse_bytes %s=0x%x %s=0x%x", i.instructionCounter, dst, i.regs[dst], s, i.regs[s])
	i.setAndSkip(dst, bits.ReverseBytes64(i.regs[s]))
}

// StoreIndirectU8 store_ind_u8 μ′↺_{φB+νX} = φA mod 2^8
func (i *Instance) StoreIndirectU8(src polkavm.Reg, base polkavm.Reg, offset uint64) error {
	log.VM.Trace().Int64("gas", i.gasRemaining).Msgf("%d: store_ind_u8 %s=0x%x %s=0x%x v1=0x%x", i.instructionCounter, src, i.regs[src], base, i.regs[base], offset)
	return i.store(i.regs[base]+offset, uint8(i.regs[src]))
}

// StoreIndirectU16 store_ind_u16 μ′↺_{φB+νX...+2} = E2(φA mod 2^16)
func (i *Instance) StoreIndirectU16(src polkavm.Reg, base polkavm.Reg, offset uint64) error {
	log.VM.Trace().Int64("gas", i.gasRemaining).Msgf("%d: store_ind_u16 %s=0x%x %s=0x%x v1=0x%x", i.instructionCounter, src, i.regs[src], base, i.regs[base], offset)
	return i.store(i.regs[base]+offset, uint16(i.regs[src]))
}

// StoreIndirectU32 store_ind_u32 μ′↺_{φB+νX...+4} = E4(φA mod 2^32)
func (i *Instance) StoreIndirectU32(src polkavm.Reg, base polkavm.Reg, offset uint64) error {
	log.VM.Trace().Int64("gas", i.gasRemaining).Msgf("%d: store_ind_u32 %s=0x%x %s=0x%x v1=0x%x", i.instructionCounter, src, i.regs[src], base, i.regs[base], offset)
	return i.store(i.regs[base]+offset, uint32(i.regs[src]))
}

// StoreIndirectU64 store_ind_u64 μ′↺_{φB+νX...+8} = E8(φA)
func (i *Instance) StoreIndirectU64(src polkavm.Reg, base polkavm.Reg, offset uint64) error {
	log.VM.Trace().Int64("gas", i.gasRemaining).Msgf("%d: store_ind_u64 %s=0x%x %s=0x%x v1=0x%x", i.instructionCounter, src, i.regs[src], base, i.regs[base], offset)
	return i.store(i.regs[base]+offset, i.regs[src])
}

// LoadIndirectU8 load_ind_u8 φ′A = μ↺_{φB+νX}
func (i *Instance) LoadIndirectU8(dst polkavm.Reg, base polkavm.Reg, offset uint64) error {
	log.VM.Trace().Int64("gas", i.gasRemaining).Msgf("%d: load_ind_u8 %s=0x%x %s=0x%x v1=0x%x", i.instructionCounter, dst, i.regs[dst], base, i.regs[base], offset)
	slice := make([]byte, 1)
	if err := i.memory.Read(i.regs[base]+offset, slice); err != nil {
		return err
	}
	i.setAndSkip(dst, uint64(slice[0]))
	return nil
}

// LoadIndirectI8 load_ind_i8 φ′A = Z−1_8(Z1(μ↺_{φB+νX}))
func (i *Instance) LoadIndirectI8(dst polkavm.Reg, base polkavm.Reg, offset uint64) error {
	log.VM.Trace().Int64("gas", i.gasRemaining).Msgf("%d: load_ind_i8 %s=0x%x %s=0x%x v1=0x%x", i.instructionCounter, dst, i.regs[dst], base, i.regs[base], offset)
	slice := make([]byte, 1)
	if err := i.memory.Read(i.regs[base]+offset, slice); err != nil {
		return err
	}
	i.setAndSkip(dst, uint64(int8(slice[0])))
	return nil
}

// LoadIndirectU16 load_ind_u16 φ′A = E−1_2 (μ↺_{φB+νX...+2})
func (i *Instance) LoadIndirectU16(dst polkavm.Reg, base polkavm.Reg, offset uint64) error {
	log.VM.Trace().Int64("gas", i.gasRemaining).Msgf("%d: load_ind_u16 %s=0x%x %s=0x%x v1=0x%x", i.instructionCounter, dst, i.regs[dst], base, i.regs[base], offset)
	var v uint16
	if err := i.load(i.regs[base]+offset, 2, &v); err != nil {
		return err
	}
	i.setAndSkip(dst, uint64(v))
	return nil
}

// LoadIndirectI16 load_ind_i16 φ′A = Z−1_8(Z2(E−1_2(μ↺_{φB+νX...+2})))
func (i *Instance) LoadIndirectI16(dst polkavm.Reg, base polkavm.Reg, offset uint64) error {
	log.VM.Trace().Int64("gas", i.gasRemaining).Msgf("%d: load_ind_i16 %s=0x%x %s=0x%x v1=0x%x", i.instructionCounter, dst, i.regs[dst], base, i.regs[base], offset)
	var v int16
	if err := i.load(i.regs[base]+offset, 2, &v); err != nil {
		return err
	}
	i.setAndSkip(dst, uint64(v))
	return nil
}

// LoadIndirectU32 load_ind_u32 φ′A = E−1_4(μ↺_{φB+νX...+4})
func (i *Instance) LoadIndirectU32(dst polkavm.Reg, base polkavm.Reg, offset uint64) error {
	log.VM.Trace().Int64("gas", i.gasRemaining).Msgf("%d: load_ind_u32 %s=0x%x %s=0x%x v1=0x%x", i.instructionCounter, dst, i.regs[dst], base, i.regs[base], offset)
	var v uint32
	if err := i.load(i.regs[base]+offset, 4, &v); err != nil {
		return err
	}
	i.setAndSkip(dst, uint64(v))
	return nil
}

// LoadIndirectI32 load_ind_i32 φ′A = Z−1_8(Z4(E−1_4(μ↺_{φB+νX...+4})))
func (i *Instance) LoadIndirectI32(dst polkavm.Reg, base polkavm.Reg, offset uint64) error {
	log.VM.Trace().Int64("gas", i.gasRemaining).Msgf("%d: load_ind_i32 %s=0x%x %s=0x%x v1=0x%x", i.instructionCounter, dst, i.regs[dst], base, i.regs[base], offset)
	var v int32
	if err := i.load(i.regs[base]+offset, 4, &v); err != nil {
		return err
	}
	i.setAndSkip(dst, uint64(v))
	return nil
}

// LoadIndirectU64 load_ind_u64 φ′A = E−1_8(μ↺_{φB+νX...+8})
func (i *Instance) LoadIndirectU64(dst polkavm.Reg, base polkavm.Reg, offset uint64) error {
	log.VM.Trace().Int64("gas", i.gasRemaining).Msgf("%d: load_ind_u64 %s=0x%x %s=0x%x v1=0x%x", i.instructionCounter, dst, i.regs[dst], base, i.regs[base], offset)
	var v uint64
	if err := i.load(i.regs[base]+offset, 8, &v); err != nil {
		return err
	}
	i.setAndSkip(dst, v)
	return nil
}

// AddImm32 add_imm_32 φ′A = X4((φB + νX) mod 2^32)
func (i *Instance) AddImm32(dst polkavm.Reg, regA polkavm.Reg, value uint64) {
	log.VM.Trace().Int64("gas", i.gasRemaining).Msgf("%d: add_imm_32 %s=0x%x %s=0x%x v1=0x%x", i.instructionCounter, dst, i.regs[dst], regA, i.regs[regA], value)
	i.setAndSkip(dst, sext(uint64(uint32(i.regs[regA]+value)), 4))
}

// AndImm and_imm ∀i ∈ N64 ∶ B8(φ′A)_i = B8(φB)_i ∧ B8(νX)_i
func (i *Instance) AndImm(dst polkavm.Reg, regA polkavm.Reg, value uint64) {
	log.VM.Trace().Int64("gas", i.gasRemaining).Msgf("%d: and_imm %s=0x%x %s=0x%x v1=0x%x", i.instructionCounter, dst, i.regs[dst], regA, i.regs[regA], value)
	i.setAndSkip(dst, (i.regs[regA])&value)
}

// XorImm xor_imm ∀i ∈ N64 ∶ B8(φ′A)i = B8(φB)_i ⊕ B8(νX)_i
func (i *Instance) XorImm(dst polkavm.Reg, regA polkavm.Reg, value uint64) {
	log.VM.Trace().Int64("gas", i.gasRemaining).Msgf("%d: xor_imm %s=0x%x %s=0x%x v1=0x%x", i.instructionCounter, dst, i.regs[dst], regA, i.regs[regA], value)
	i.setAndSkip(dst, (i.regs[regA])^value)
}

// OrImm or_imm ∀i ∈ N64 ∶ B8(φ′A)i = B8(φB)_i ∨ B8(νX)_i
func (i *Instance) OrImm(dst polkavm.Reg, regA polkavm.Reg, value uint64) {
	log.VM.Trace().Int64("gas", i.gasRemaining).Msgf("%d: or_imm %s=0x%x %s=0x%x v1=0x%x", i.instructionCounter, dst, i.regs[dst], regA, i.regs[regA], value)
	i.setAndSkip(dst, (i.regs[regA])|value)
}

// MulImm32 mul_imm_32 φ′A = X4((φB ⋅ νX) mod 2^32)
func (i *Instance) MulImm32(dst polkavm.Reg, regA polkavm.Reg, value uint64) {
	log.VM.Trace().Int64("gas", i.gasRemaining).Msgf("%d: mul_imm_32 %s=0x%x %s=0x%x v1=0x%x", i.instructionCounter, dst, i.regs[dst], regA, i.regs[regA], value)
	i.setAndSkip(dst, sext(uint64(uint32(i.regs[regA]*value)), 4))
}

// SetLessThanUnsignedImm set_lt_u_imm φ′A = φB < νX
func (i *Instance) SetLessThanUnsignedImm(dst polkavm.Reg, regA polkavm.Reg, value uint64) {
	log.VM.Trace().Int64("gas", i.gasRemaining).Msgf("%d: set_lt_u_imm %s=0x%x %s=0x%x v1=0x%x", i.instructionCounter, dst, i.regs[dst], regA, i.regs[regA], value)
	i.setAndSkip(dst, bool2uint64((i.regs[regA]) < value))
}

// SetLessThanSignedImm set_lt_s_imm φ′A = Z8(φB) < Z8(νX)
func (i *Instance) SetLessThanSignedImm(dst polkavm.Reg, regA polkavm.Reg, value uint64) {
	log.VM.Trace().Int64("gas", i.gasRemaining).Msgf("%d: set_lt_s_imm %s=0x%x %s=0x%x v1=0x%x", i.instructionCounter, dst, i.regs[dst], regA, i.regs[regA], value)
	i.setAndSkip(dst, bool2uint64(int64(i.regs[regA]) < int64(value)))
}

// ShiftLogicalLeftImm32 shlo_l_imm_32 φ′A = X4((φB ⋅ 2^νX mod 32) mod 2^32)
func (i *Instance) ShiftLogicalLeftImm32(dst polkavm.Reg, regA polkavm.Reg, value uint64) {
	log.VM.Trace().Int64("gas", i.gasRemaining).Msgf("%d: shlo_l_imm_32 %s=0x%x %s=0x%x v1=0x%x", i.instructionCounter, dst, i.regs[dst], regA, i.regs[regA], value)
	i.setAndSkip(dst, sext(uint64(uint32(i.regs[regA])<<value), 4))
}

// ShiftLogicalRightImm32 shlo_r_imm_32 φ′A = X4(⌊ φB mod 2^32 ÷ 2^νX mod 32 ⌋)
func (i *Instance) ShiftLogicalRightImm32(dst polkavm.Reg, regA polkavm.Reg, value uint64) {
	log.VM.Trace().Int64("gas", i.gasRemaining).Msgf("%d: shlo_r_imm_32 %s=0x%x %s=0x%x v1=0x%x", i.instructionCounter, dst, i.regs[dst], regA, i.regs[regA], value)
	i.setAndSkip(dst, sext(uint64(uint32(i.regs[regA])>>value), 4))
}

// ShiftArithmeticRightImm32 shar_r_imm_32 φ′A = Z−1_8(⌊ Z4(φB mod 2^32) ÷ 2^νX mod 32 ⌋)
func (i *Instance) ShiftArithmeticRightImm32(dst polkavm.Reg, regA polkavm.Reg, value uint64) {
	log.VM.Trace().Int64("gas", i.gasRemaining).Msgf("%d: shar_r_imm_32 %s=0x%x %s=0x%x v1=0x%x", i.instructionCounter, dst, i.regs[dst], regA, i.regs[regA], value)
	i.setAndSkip(dst, uint64(int32(uint32(i.regs[regA]))>>value))
}

// NegateAndAddImm32 neg_add_imm_32 φ′A = X4((νX + 2^32 − φB) mod 2^32)
func (i *Instance) NegateAndAddImm32(dst polkavm.Reg, regA polkavm.Reg, value uint64) {
	log.VM.Trace().Int64("gas", i.gasRemaining).Msgf("%d: neg_add_imm_32 %s=0x%x %s=0x%x v1=0x%x", i.instructionCounter, dst, i.regs[dst], regA, i.regs[regA], value)
	i.setAndSkip(dst, sext(uint64(uint32(value-i.regs[regA])), 4))
}

// SetGreaterThanUnsignedImm set_gt_u_imm φ′A = φB > νX
func (i *Instance) SetGreaterThanUnsignedImm(dst polkavm.Reg, regA polkavm.Reg, value uint64) {
	log.VM.Trace().Int64("gas", i.gasRemaining).Msgf("%d: set_gt_u_imm %s=0x%x %s=0x%x v1=0x%x", i.instructionCounter, dst, i.regs[dst], regA, i.regs[regA], value)
	i.setAndSkip(dst, bool2uint64(i.regs[regA] > value))
}

// SetGreaterThanSignedImm set_gt_s_imm φ′A = Z8(φB) > Z8(νX)
func (i *Instance) SetGreaterThanSignedImm(dst polkavm.Reg, regA polkavm.Reg, value uint64) {
	log.VM.Trace().Int64("gas", i.gasRemaining).Msgf("%d: set_gt_s_imm %s=0x%x %s=0x%x v1=0x%x", i.instructionCounter, dst, i.regs[dst], regA, i.regs[regA], value)
	i.setAndSkip(dst, bool2uint64(int64(i.regs[regA]) > int64(value)))
}

// ShiftLogicalLeftImmAlt32 shlo_l_imm_alt_32 φ′A = X4((νX ⋅ 2φB mod 32) mod 2^32)
func (i *Instance) ShiftLogicalLeftImmAlt32(dst polkavm.Reg, regB polkavm.Reg, value uint64) {
	log.VM.Trace().Int64("gas", i.gasRemaining).Msgf("%d: shlo_l_imm_alt_32 %s=0x%x %s=0x%x v1=0x%x", i.instructionCounter, dst, i.regs[dst], regB, i.regs[regB], value)
	i.setAndSkip(dst, sext(uint64(uint32(value<<i.regs[regB])), 4))
}

// ShiftLogicalRightImmAlt32 shlo_r_imm_alt_32 φ′A = X4(⌊ νX mod 2^32 ÷ 2^φB mod 32 ⌋)
func (i *Instance) ShiftLogicalRightImmAlt32(dst polkavm.Reg, regB polkavm.Reg, value uint64) {
	log.VM.Trace().Int64("gas", i.gasRemaining).Msgf("%d: shlo_r_imm_alt_32 %s=0x%x %s=0x%x v1=0x%x", i.instructionCounter, dst, i.regs[dst], regB, i.regs[regB], value)
	i.setAndSkip(dst, sext(uint64(uint32(value)>>uint32(i.regs[regB])), 4))
}

// ShiftArithmeticRightImmAlt32 shar_r_imm_alt_32 φ′A = Z−1_8(⌊ Z4(νX mod 2^32) ÷ 2φB mod 32 ⌋)
func (i *Instance) ShiftArithmeticRightImmAlt32(dst polkavm.Reg, regB polkavm.Reg, value uint64) {
	log.VM.Trace().Int64("gas", i.gasRemaining).Msgf("%d: shar_r_imm_alt_32 %s=0x%x %s=0x%x v1=0x%x", i.instructionCounter, dst, i.regs[dst], regB, i.regs[regB], value)
	i.setAndSkip(dst, uint64(int32(uint32(value))>>uint32(i.regs[regB])))
}

// CmovIfZeroImm cmov_iz_imm φ′A = νX if φB = 0 otherwise φA
func (i *Instance) CmovIfZeroImm(dst polkavm.Reg, c polkavm.Reg, s uint64) {
	log.VM.Trace().Int64("gas", i.gasRemaining).Msgf("%d: cmov_iz_imm %s=0x%x %s=0x%x v1=0x%x", i.instructionCounter, dst, i.regs[dst], c, i.regs[c], s)
	if i.regs[c] == 0 {
		i.regs[dst] = s
	}
	i.skip()
}

// CmovIfNotZeroImm cmov_nz_imm φ′A = νX if φB ≠ 0 otherwise φA
func (i *Instance) CmovIfNotZeroImm(dst polkavm.Reg, c polkavm.Reg, s uint64) {
	log.VM.Trace().Int64("gas", i.gasRemaining).Msgf("%d: cmov_nz_imm %s=0x%x %s=0x%x v1=0x%x", i.instructionCounter, dst, i.regs[dst], c, i.regs[c], s)
	if i.regs[c] != 0 {
		i.regs[dst] = s
	}

	i.skip()
}

// AddImm64 add_imm_64 φ′A = (φB + νX) mod 2^64
func (i *Instance) AddImm64(dst polkavm.Reg, regA polkavm.Reg, value uint64) {
	log.VM.Trace().Int64("gas", i.gasRemaining).Msgf("%d: add_imm_64 %s=0x%x %s=0x%x v1=0x%x", i.instructionCounter, dst, i.regs[dst], regA, i.regs[regA], value)
	i.setAndSkip(dst, i.regs[regA]+value)
}

// MulImm64 mul_imm_64 φ′A = (φB ⋅ νX) mod 2^64
func (i *Instance) MulImm64(dst polkavm.Reg, regA polkavm.Reg, value uint64) {
	log.VM.Trace().Int64("gas", i.gasRemaining).Msgf("%d: mul_imm_64 %s=0x%x %s=0x%x v1=0x%x", i.instructionCounter, dst, i.regs[dst], regA, i.regs[regA], value)
	i.setAndSkip(dst, i.regs[regA]*value)
}

// ShiftLogicalLeftImm64 shlo_l_imm_64 φ′A = X8((φB ⋅ 2^νX mod 64) mod 2^64)
func (i *Instance) ShiftLogicalLeftImm64(dst polkavm.Reg, regA polkavm.Reg, value uint64) {
	log.VM.Trace().Int64("gas", i.gasRemaining).Msgf("%d: shlo_l_imm_64 %s=0x%x %s=0x%x v1=0x%x", i.instructionCounter, dst, i.regs[dst], regA, i.regs[regA], value)
	i.setAndSkip(dst, sext(i.regs[regA]<<value, 8))
}

// ShiftLogicalRightImm64 shlo_r_imm_64 φ′A = X8(⌊ φB ÷ 2^νX mod 64 ⌋)
func (i *Instance) ShiftLogicalRightImm64(dst polkavm.Reg, regA polkavm.Reg, value uint64) {
	log.VM.Trace().Int64("gas", i.gasRemaining).Msgf("%d: shlo_r_imm_64 %s=0x%x %s=0x%x v1=0x%x", i.instructionCounter, dst, i.regs[dst], regA, i.regs[regA], value)
	i.setAndSkip(dst, sext(i.regs[regA]>>value, 8))
}

// ShiftArithmeticRightImm64 shar_r_imm_64 φ′A = Z−1_8(⌊ Z8(φB) ÷ 2νX mod 64 ⌋)
func (i *Instance) ShiftArithmeticRightImm64(dst polkavm.Reg, regA polkavm.Reg, value uint64) {
	log.VM.Trace().Int64("gas", i.gasRemaining).Msgf("%d: shar_r_imm_64 %s=0x%x %s=0x%x v1=0x%x", i.instructionCounter, dst, i.regs[dst], regA, i.regs[regA], value)
	i.setAndSkip(dst, uint64(int64(i.regs[regA])>>value))
}

// NegateAndAddImm64 neg_add_imm_64 φ′A = (νX + 2^64 − φB) mod 2^64
func (i *Instance) NegateAndAddImm64(dst polkavm.Reg, regA polkavm.Reg, value uint64) {
	log.VM.Trace().Int64("gas", i.gasRemaining).Msgf("%d: neg_add_imm_64 %s=0x%x %s=0x%x v1=0x%x", i.instructionCounter, dst, i.regs[dst], regA, i.regs[regA], value)
	i.setAndSkip(dst, value-i.regs[regA])
}

// ShiftLogicalLeftImmAlt64 shlo_l_imm_alt_64 φ′A = (νX ⋅ 2φB mod 64) mod 2^64
func (i *Instance) ShiftLogicalLeftImmAlt64(dst polkavm.Reg, regB polkavm.Reg, value uint64) {
	log.VM.Trace().Int64("gas", i.gasRemaining).Msgf("%d: shlo_l_imm_alt_64 %s=0x%x %s=0x%x v1=0x%x", i.instructionCounter, dst, i.regs[dst], regB, i.regs[regB], value)
	i.setAndSkip(dst, value<<(i.regs[regB]&63))
}

// ShiftLogicalRightImmAlt64 shlo_r_imm_alt_64 φ′A = ⌊ νX ÷ 2^φB mod 64 ⌋
func (i *Instance) ShiftLogicalRightImmAlt64(dst polkavm.Reg, regB polkavm.Reg, value uint64) {
	log.VM.Trace().Int64("gas", i.gasRemaining).Msgf("%d: shlo_r_imm_alt_64 %s=0x%x %s=0x%x v1=0x%x", i.instructionCounter, dst, i.regs[dst], regB, i.regs[regB], value)
	i.setAndSkip(dst, value>>(i.regs[regB]&63))
}

// ShiftArithmeticRightImmAlt64 shar_r_imm_alt_64 φ′A = Z−1_8(⌊ Z8(νX) ÷ 2φB mod 64 ⌋)
func (i *Instance) ShiftArithmeticRightImmAlt64(dst polkavm.Reg, regB polkavm.Reg, value uint64) {
	log.VM.Trace().Int64("gas", i.gasRemaining).Msgf("%d: shar_r_imm_alt_64 %s=0x%x %s=0x%x v1=0x%x", i.instructionCounter, dst, i.regs[dst], regB, i.regs[regB], value)
	i.setAndSkip(dst, uint64(int32(value)>>i.regs[regB]))
}

// RotateRight64Imm rot_r_64_imm ∀i ∈ N64 ∶ B8(φ′A)_i = B8(φB)_{(i+νX) mod 64}
func (i *Instance) RotateRight64Imm(dst polkavm.Reg, regA polkavm.Reg, value uint64) {
	log.VM.Trace().Int64("gas", i.gasRemaining).Msgf("%d: rot_r_64_imm %s=0x%x %s=0x%x v1=0x%x", i.instructionCounter, dst, i.regs[dst], regA, i.regs[regA], value)
	i.setAndSkip(dst, bits.RotateLeft64(i.regs[regA], -int(value)))
}

// RotateRight64ImmAlt rot_r_64_imm_alt ∀i ∈ N64 ∶ B8(φ′A)i = B8(νX)_{(i+φB) mod 64}
func (i *Instance) RotateRight64ImmAlt(dst polkavm.Reg, regA polkavm.Reg, value uint64) {
	log.VM.Trace().Int64("gas", i.gasRemaining).Msgf("%d: rot_r_64_imm_alt %s=0x%x %s=0x%x v1=0x%x", i.instructionCounter, dst, i.regs[dst], regA, i.regs[regA], value)
	i.setAndSkip(dst, bits.RotateLeft64(value, -int(i.regs[regA])))
}

// RotateRight32Imm rot_r_32_imm φ′A = X4(x) where x ∈ N2^32, ∀i ∈ N32 ∶ B4(x)_i = B4(φB)_{(i+νX ) mod 32}
func (i *Instance) RotateRight32Imm(dst polkavm.Reg, regA polkavm.Reg, value uint64) {
	log.VM.Trace().Int64("gas", i.gasRemaining).Msgf("%d: rot_r_32_imm %s=0x%x %s=0x%x v1=0x%x", i.instructionCounter, dst, i.regs[dst], regA, i.regs[regA], value)
	i.setAndSkip(dst, sext(uint64(bits.RotateLeft32(uint32(i.regs[regA]), -int(value))), 4))
}

// RotateRight32ImmAlt rot_r_32_imm_alt φ′A = X4(x) where x ∈ N2^32, ∀i ∈ N32 ∶ B4(x)_i = B4(νX)_{(i+φB) mod 32}
func (i *Instance) RotateRight32ImmAlt(dst polkavm.Reg, regA polkavm.Reg, value uint64) {
	log.VM.Trace().Int64("gas", i.gasRemaining).Msgf("%d: rot_r_32_imm_alt %s=0x%x %s=0x%x v1=0x%x", i.instructionCounter, dst, i.regs[dst], regA, i.regs[regA], value)
	i.setAndSkip(dst, sext(uint64(bits.RotateLeft32(uint32(value), -int(uint32(i.regs[regA])))), 4))
}

// BranchEq branch_eq branch(νX, φA = φB)
func (i *Instance) BranchEq(regA polkavm.Reg, regB polkavm.Reg, target uint64) error {
	log.VM.Trace().Int64("gas", i.gasRemaining).Msgf("%d: branch_eq %s=0x%x %s=0x%x v1=0x%x", i.instructionCounter, regA, i.regs[regA], regB, i.regs[regB], target)
	return i.branch(i.regs[regA] == i.regs[regB], target)
}

// BranchNotEq branch_ne branch(νX, φA ≠ φB)
func (i *Instance) BranchNotEq(regA polkavm.Reg, regB polkavm.Reg, target uint64) error {
	log.VM.Trace().Int64("gas", i.gasRemaining).Msgf("%d: branch_ne %s=0x%x %s=0x%x v1=0x%x", i.instructionCounter, regA, i.regs[regA], regB, i.regs[regB], target)
	return i.branch(i.regs[regA] != i.regs[regB], target)
}

// BranchLessUnsigned branch_lt_u branch(νX, φA < φB)
func (i *Instance) BranchLessUnsigned(regA polkavm.Reg, regB polkavm.Reg, target uint64) error {
	log.VM.Trace().Int64("gas", i.gasRemaining).Msgf("%d: branch_lt_u %s=0x%x %s=0x%x v1=0x%x", i.instructionCounter, regA, i.regs[regA], regB, i.regs[regB], target)
	return i.branch(i.regs[regA] < i.regs[regB], target)
}

// BranchLessSigned branch_lt_s branch(νX, Z8(φA) < Z8(φB))
func (i *Instance) BranchLessSigned(regA polkavm.Reg, regB polkavm.Reg, target uint64) error {
	log.VM.Trace().Int64("gas", i.gasRemaining).Msgf("%d: branch_lt_s %s=0x%x %s=0x%x v1=0x%x", i.instructionCounter, regA, i.regs[regA], regB, i.regs[regB], target)
	return i.branch(int64(i.regs[regA]) < int64(i.regs[regB]), target)
}

// BranchGreaterOrEqualUnsigned branch_ge_u branch(νX, φA ≥ φB)
func (i *Instance) BranchGreaterOrEqualUnsigned(regA polkavm.Reg, regB polkavm.Reg, target uint64) error {
	log.VM.Trace().Int64("gas", i.gasRemaining).Msgf("%d: branch_ge_u %s=0x%x %s=0x%x v1=0x%x", i.instructionCounter, regA, i.regs[regA], regB, i.regs[regB], target)
	return i.branch(i.regs[regA] >= i.regs[regB], target)
}

// BranchGreaterOrEqualSigned branch_ge_s branch(νX, Z8(φA) ≥ Z8(φB))
func (i *Instance) BranchGreaterOrEqualSigned(regA polkavm.Reg, regB polkavm.Reg, target uint64) error {
	log.VM.Trace().Int64("gas", i.gasRemaining).Msgf("%d: branch_ge_s %s=0x%x %s=0x%x v1=0x%x", i.instructionCounter, regA, i.regs[regA], regB, i.regs[regB], target)
	return i.branch(int64(i.regs[regA]) >= int64(i.regs[regB]), target)
}

// LoadImmAndJumpIndirect load_imm_jump_ind djump((φB + νY) mod 232), φ′A = νX
func (i *Instance) LoadImmAndJumpIndirect(regA polkavm.Reg, base polkavm.Reg, value, offset uint64) error {
	log.VM.Trace().Int64("gas", i.gasRemaining).Msgf("%d: load_imm_jump_ind %s=0x%x %s=0x%x v1=0x%x v2=0x%x", i.instructionCounter, regA, i.regs[regA], base, i.regs[base], value, offset)
	target := i.regs[base] + offset
	i.regs[regA] = value
	return i.djump(target)
}

// Add32 add_32 φ′D = X4((φA + φB) mod 2^32)
func (i *Instance) Add32(dst polkavm.Reg, regA, regB polkavm.Reg) {
	log.VM.Trace().Int64("gas", i.gasRemaining).Msgf("%d: add_32 %s=0x%x %s=0x%x %s=0x%x", i.instructionCounter, dst, i.regs[dst], regA, i.regs[regA], regB, i.regs[regB])
	i.setAndSkip(dst, sext(uint64(uint32(i.regs[regA]+i.regs[regB])), 4))
}

// Sub32 sub_32 φ′D = X4((φA + 2^32 − (φB mod 2^32)) mod 2^32)
func (i *Instance) Sub32(dst polkavm.Reg, regA, regB polkavm.Reg) {
	log.VM.Trace().Int64("gas", i.gasRemaining).Msgf("%d: sub_32 %s=0x%x %s=0x%x %s=0x%x", i.instructionCounter, dst, i.regs[dst], regA, i.regs[regA], regB, i.regs[regB])
	i.setAndSkip(dst, sext(uint64(uint32(i.regs[regA]-i.regs[regB])), 4))
}

// Mul32 mul_32 φ′D = X4((φA ⋅ φB) mod 2^32)
func (i *Instance) Mul32(dst polkavm.Reg, regA, regB polkavm.Reg) {
	log.VM.Trace().Int64("gas", i.gasRemaining).Msgf("%d: mul_32 %s=0x%x %s=0x%x %s=0x%x", i.instructionCounter, dst, i.regs[dst], regA, i.regs[regA], regB, i.regs[regB])
	i.setAndSkip(dst, sext(uint64(uint32(i.regs[regA]*i.regs[regB])), 4))
}

// DivUnsigned32 div_u_32 φ′D = 2^64 − 1 if φB mod 2^32 = 0 otherwise X4(⌊ (φA mod 2^32) ÷ (φB mod 2^32) ⌋)
func (i *Instance) DivUnsigned32(dst polkavm.Reg, regA, regB polkavm.Reg) {
	log.VM.Trace().Int64("gas", i.gasRemaining).Msgf("%d: div_u_32 %s=0x%x %s=0x%x %s=0x%x", i.instructionCounter, dst, i.regs[dst], regA, i.regs[regA], regB, i.regs[regB])
	lhs, rhs := uint32(i.regs[regA]), uint32(i.regs[regB])
	if rhs == 0 {
		i.regs[dst] = math.MaxUint64
	} else {
		i.regs[dst] = sext(uint64(lhs/rhs), 4)
	}
	i.skip()
}

// DivSigned32 div_s_32 φ′D =
// ⎧ 2^64 − 1 			if b = 0
// ⎨ Z−1_8(a) 			if a = −2^31 ∧ b = −1
// ⎩ Z−1_8 (rtz(a ÷ b)) otherwise
// where a = Z4(φA mod 2^32), b = Z4(φB mod 2^32)
func (i *Instance) DivSigned32(dst polkavm.Reg, regA, regB polkavm.Reg) {
	log.VM.Trace().Int64("gas", i.gasRemaining).Msgf("%d: div_s_32 %s=0x%x %s=0x%x %s=0x%x", i.instructionCounter, dst, i.regs[dst], regA, i.regs[regA], regB, i.regs[regB])
	lhs := int32(uint32(i.regs[regA]))
	rhs := int32(uint32(i.regs[regB]))
	if rhs == 0 {
		i.regs[dst] = math.MaxUint64
	} else if lhs == math.MinInt32 && rhs == -1 {
		i.regs[dst] = uint64(lhs)
	} else {
		i.regs[dst] = uint64(lhs / rhs)
	}
	i.skip()
}

// RemUnsigned32 rem_u_32 φ′D = X4(φA mod 2^32) if φB mod 2^32 = 0 otherwise X4((φA mod 2^32) mod (φB mod 2^32))
func (i *Instance) RemUnsigned32(dst polkavm.Reg, regA, regB polkavm.Reg) {
	log.VM.Trace().Int64("gas", i.gasRemaining).Msgf("%d: rem_u_32 %s=0x%x %s=0x%x %s=0x%x", i.instructionCounter, dst, i.regs[dst], regA, i.regs[regA], regB, i.regs[regB])
	lhs, rhs := uint32(i.regs[regA]), uint32(i.regs[regB])
	if rhs == 0 {
		i.regs[dst] = sext(uint64(lhs), 4)
	} else {
		i.regs[dst] = sext(uint64(lhs%rhs), 4)
	}
	i.skip()
}

// RemSigned32 rem_s_32 φ′D =
// ⎧ 0			 		if a = −2^31 ∧ b = −1
// ⎨
// ⎩ Z−1_8 (smod(a, b)) otherwise
// where a = Z4(φA mod 2^32), b = Z4(φB mod 2^32)
func (i *Instance) RemSigned32(dst polkavm.Reg, regA, regB polkavm.Reg) {
	log.VM.Trace().Int64("gas", i.gasRemaining).Msgf("%d: rem_s_32 %s=0x%x %s=0x%x %s=0x%x", i.instructionCounter, dst, i.regs[dst], regA, i.regs[regA], regB, i.regs[regB])
	lhs := int32(uint32(i.regs[regA]))
	rhs := int32(uint32(i.regs[regB]))
	if lhs == math.MinInt32 && rhs == -1 {
		i.regs[dst] = uint64(0)
	} else {
		i.regs[dst] = uint64(smod32(lhs, rhs))
	}
	i.skip()
}

// ShiftLogicalLeft32 shlo_l_32 φ′D = X4((φA ⋅ 2φB mod 32) mod 2^32)
func (i *Instance) ShiftLogicalLeft32(dst polkavm.Reg, regA, regB polkavm.Reg) {
	log.VM.Trace().Int64("gas", i.gasRemaining).Msgf("%d: shlo_l_32 %s=0x%x %s=0x%x %s=0x%x", i.instructionCounter, dst, i.regs[dst], regA, i.regs[regA], regB, i.regs[regB])
	i.setAndSkip(dst, sext(uint64(uint32(i.regs[regA])<<(uint32(i.regs[regB])%32)), 4))
}

// ShiftLogicalRight32 shlo_r_32 φ′D = X4(⌊ (φA mod 2^32) ÷ 2φB mod 32 ⌋)
func (i *Instance) ShiftLogicalRight32(dst polkavm.Reg, regA, regB polkavm.Reg) {
	log.VM.Trace().Int64("gas", i.gasRemaining).Msgf("%d: shlo_r_32 %s=0x%x %s=0x%x %s=0x%x", i.instructionCounter, dst, i.regs[dst], regA, i.regs[regA], regB, i.regs[regB])
	i.setAndSkip(dst, sext(uint64(uint32(i.regs[regA])>>(uint32(i.regs[regB])%32)), 4))
}

// ShiftArithmeticRight32 shar_r_32 φ′D = Z−1_8(⌊ Z4(φA mod 2^32) ÷ 2φB mod 32 ⌋)
func (i *Instance) ShiftArithmeticRight32(dst polkavm.Reg, regA, regB polkavm.Reg) {
	log.VM.Trace().Int64("gas", i.gasRemaining).Msgf("%d: shar_r_32 %s=0x%x %s=0x%x %s=0x%x", i.instructionCounter, dst, i.regs[dst], regA, i.regs[regA], regB, i.regs[regB])
	shiftAmount := uint32(i.regs[regB]) % 32
	shiftedValue := int32(uint32(i.regs[regA])) >> shiftAmount
	i.setAndSkip(dst, uint64(shiftedValue))
}

// Add64 add_64 φ′D = (φA + φB) mod 2^64
func (i *Instance) Add64(dst polkavm.Reg, regA, regB polkavm.Reg) {
	log.VM.Trace().Int64("gas", i.gasRemaining).Msgf("%d: add_64 %s=0x%x %s=0x%x %s=0x%x", i.instructionCounter, dst, i.regs[dst], regA, i.regs[regA], regB, i.regs[regB])
	i.setAndSkip(dst, i.regs[regA]+i.regs[regB])
}

// Sub64 sub_64 φ′D = (φA + 2^64 − φB) mod 2^64
func (i *Instance) Sub64(dst polkavm.Reg, regA, regB polkavm.Reg) {
	log.VM.Trace().Int64("gas", i.gasRemaining).Msgf("%d: sub_64 %s=0x%x %s=0x%x %s=0x%x", i.instructionCounter, dst, i.regs[dst], regA, i.regs[regA], regB, i.regs[regB])
	i.setAndSkip(dst, i.regs[regA]-i.regs[regB])
}

// Mul64 mul_64 φ′D = (φA ⋅ φB) mod 2^64
func (i *Instance) Mul64(dst polkavm.Reg, regA, regB polkavm.Reg) {
	log.VM.Trace().Int64("gas", i.gasRemaining).Msgf("%d: mul_64 %s=0x%x %s=0x%x %s=0x%x", i.instructionCounter, dst, i.regs[dst], regA, i.regs[regA], regB, i.regs[regB])
	i.setAndSkip(dst, i.regs[regA]*i.regs[regB])
}

// DivUnsigned64 div_u_64 φ′D = 2^64 − 1 if φB = 0 otherwise ⌊ φA ÷ φB ⌋
func (i *Instance) DivUnsigned64(dst polkavm.Reg, regA, regB polkavm.Reg) {
	log.VM.Trace().Int64("gas", i.gasRemaining).Msgf("%d: div_u_64 %s=0x%x %s=0x%x %s=0x%x", i.instructionCounter, dst, i.regs[dst], regA, i.regs[regA], regB, i.regs[regB])
	lhs, rhs := i.regs[regA], i.regs[regB]
	if rhs == 0 {
		i.regs[dst] = math.MaxUint64
	} else {
		i.regs[dst] = lhs / rhs
	}
	i.skip()
}

// DivSigned64 div_s_64 φ′D =
// ⎧ 2^64 − 1 						if φB = 0
// ⎨ φA								if Z8(φA) = −2^63 ∧ Z8(φB) = −1
// ⎩ Z−1_8(rtz(Z8(φA) ÷ Z8(φB))) 	otherwise
func (i *Instance) DivSigned64(dst polkavm.Reg, regA, regB polkavm.Reg) {
	log.VM.Trace().Int64("gas", i.gasRemaining).Msgf("%d: div_s_64 %s=0x%x %s=0x%x %s=0x%x", i.instructionCounter, dst, i.regs[dst], regA, i.regs[regA], regB, i.regs[regB])
	lhs := int64(i.regs[regA])
	rhs := int64(i.regs[regB])
	if rhs == 0 {
		i.regs[dst] = math.MaxUint64
	} else if lhs == math.MinInt64 && rhs == -1 {
		i.regs[dst] = i.regs[regA]
	} else {
		i.regs[dst] = uint64(lhs / rhs)
	}
	i.skip()
}

// RemUnsigned64 rem_u_64 φ′D = φA if φB = 0 otherwise φA mod φB
func (i *Instance) RemUnsigned64(dst polkavm.Reg, regA, regB polkavm.Reg) {
	log.VM.Trace().Int64("gas", i.gasRemaining).Msgf("%d: rem_u_64 %s=0x%x %s=0x%x %s=0x%x", i.instructionCounter, dst, i.regs[dst], regA, i.regs[regA], regB, i.regs[regB])
	lhs, rhs := i.regs[regA], i.regs[regB]
	if rhs == 0 {
		i.regs[dst] = lhs
	} else {
		i.regs[dst] = lhs % rhs
	}
	i.skip()
}

// RemSigned64 rem_s_64 φ′D =
// ⎧ φA						 	 if φB = 0
// ⎨ 0 							 if Z8(φA) = −2^63 ∧ Z8(φB) = −1
// ⎩ Z−1_8(smod(Z8(φA), Z8(φB))) otherwise
func (i *Instance) RemSigned64(dst polkavm.Reg, regA, regB polkavm.Reg) {
	log.VM.Trace().Int64("gas", i.gasRemaining).Msgf("%d: rem_s_64 %s=0x%x %s=0x%x %s=0x%x", i.instructionCounter, dst, i.regs[dst], regA, i.regs[regA], regB, i.regs[regB])
	lhs, rhs := int64(i.regs[regA]), int64(i.regs[regB])
	if lhs == math.MinInt64 && rhs == -1 {
		i.regs[dst] = 0
	} else {
		i.regs[dst] = uint64(smod64(lhs, rhs))
	}
	i.skip()
}

// ShiftLogicalLeft64 shlo_l_64 φ′D = (φA ⋅ 2φB mod 64) mod 2^64
func (i *Instance) ShiftLogicalLeft64(dst polkavm.Reg, regA, regB polkavm.Reg) {
	log.VM.Trace().Int64("gas", i.gasRemaining).Msgf("%d: shlo_l_64 %s=0x%x %s=0x%x %s=0x%x", i.instructionCounter, dst, i.regs[dst], regA, i.regs[regA], regB, i.regs[regB])
	shiftAmount := i.regs[regB] % 64
	shiftedValue := i.regs[regA] << shiftAmount
	i.setAndSkip(dst, shiftedValue)
}

// ShiftLogicalRight64 shlo_r_64 φ′D = ⌊ φA ÷ 2φB mod 64 ⌋
func (i *Instance) ShiftLogicalRight64(dst polkavm.Reg, regA, regB polkavm.Reg) {
	log.VM.Trace().Int64("gas", i.gasRemaining).Msgf("%d: shlo_r_64 %s=0x%x %s=0x%x %s=0x%x", i.instructionCounter, dst, i.regs[dst], regA, i.regs[regA], regB, i.regs[regB])
	i.setAndSkip(dst, i.regs[regA]>>(i.regs[regB]%64))
}

// ShiftArithmeticRight64 shar_r_64 φ′D = Z−1_8(⌊ Z8(φA) ÷ 2φB mod 64 ⌋)
func (i *Instance) ShiftArithmeticRight64(dst polkavm.Reg, regA, regB polkavm.Reg) {
	log.VM.Trace().Int64("gas", i.gasRemaining).Msgf("%d: shar_r_64 %s=0x%x %s=0x%x %s=0x%x", i.instructionCounter, dst, i.regs[dst], regA, i.regs[regA], regB, i.regs[regB])
	shiftAmount := i.regs[regB] % 64
	shiftedValue := int64(i.regs[regA]) >> shiftAmount
	i.setAndSkip(dst, uint64(shiftedValue))
}

// And and ∀i ∈ N64 ∶ B8(φ′D)_i = B8(φA)_i ∧ B8(φB)_i
func (i *Instance) And(dst polkavm.Reg, regA, regB polkavm.Reg) {
	log.VM.Trace().Int64("gas", i.gasRemaining).Msgf("%d: and %s=0x%x %s=0x%x %s=0x%x", i.instructionCounter, dst, i.regs[dst], regA, i.regs[regA], regB, i.regs[regB])
	i.setAndSkip(dst, i.regs[regA]&i.regs[regB])
}

// Xor xor ∀i ∈ N64 ∶ B8(φ′D)_i = B8(φA)_i ⊕ B8(φB)_i
func (i *Instance) Xor(dst polkavm.Reg, regA, regB polkavm.Reg) {
	log.VM.Trace().Int64("gas", i.gasRemaining).Msgf("%d: xor %s=0x%x %s=0x%x %s=0x%x", i.instructionCounter, dst, i.regs[dst], regA, i.regs[regA], regB, i.regs[regB])
	i.setAndSkip(dst, i.regs[regA]^i.regs[regB])
}

// Or or ∀i ∈ N64 ∶ B8(φ′D)_i = B8(φA)_i ∨ B8(φB)_i
func (i *Instance) Or(dst polkavm.Reg, regA, regB polkavm.Reg) {
	log.VM.Trace().Int64("gas", i.gasRemaining).Msgf("%d: or %s=0x%x %s=0x%x %s=0x%x", i.instructionCounter, dst, i.regs[dst], regA, i.regs[regA], regB, i.regs[regB])
	i.setAndSkip(dst, i.regs[regA]|i.regs[regB])
}

// MulUpperSignedSigned mul_upper_s_s φ′D = Z−1_8(⌊ (Z8(φA) ⋅ Z8(φB)) ÷ 2^64 ⌋)
func (i *Instance) MulUpperSignedSigned(dst polkavm.Reg, regA, regB polkavm.Reg) {
	log.VM.Trace().Int64("gas", i.gasRemaining).Msgf("%d: mul_upper_s_s %s=0x%x %s=0x%x %s=0x%x", i.instructionCounter, dst, i.regs[dst], regA, i.regs[regA], regB, i.regs[regB])
	lhs := big.NewInt(int64(i.regs[regA]))
	rhs := big.NewInt(int64(i.regs[regB]))
	mul := lhs.Mul(lhs, rhs)
	i.setAndSkip(dst, uint64(mul.Rsh(mul, 64).Int64()))
}

// MulUpperUnsignedUnsigned mul_upper_u_u φ′D = ⌊ (φA ⋅ φB ) ÷ 2^64 ⌋
func (i *Instance) MulUpperUnsignedUnsigned(dst polkavm.Reg, regA, regB polkavm.Reg) {
	log.VM.Trace().Int64("gas", i.gasRemaining).Msgf("%d: mul_upper_u_u %s=0x%x %s=0x%x %s=0x%x", i.instructionCounter, dst, i.regs[dst], regA, i.regs[regA], regB, i.regs[regB])
	lhs := (&big.Int{}).SetUint64(i.regs[regA])
	rhs := (&big.Int{}).SetUint64(i.regs[regB])
	mul := lhs.Mul(lhs, rhs)
	i.setAndSkip(dst, uint64(mul.Rsh(mul, 64).Int64()))
}

// MulUpperSignedUnsigned mul_upper_s_u φ′D = Z−1_8(⌊ (Z8(φA) ⋅ φB) ÷ 2^64 ⌋)
func (i *Instance) MulUpperSignedUnsigned(dst polkavm.Reg, regA, regB polkavm.Reg) {
	log.VM.Trace().Int64("gas", i.gasRemaining).Msgf("%d: mul_upper_s_u %s=0x%x %s=0x%x %s=0x%x", i.instructionCounter, dst, i.regs[dst], regA, i.regs[regA], regB, i.regs[regB])
	lhs := big.NewInt(int64(i.regs[regA]))
	rhs := (&big.Int{}).SetUint64(i.regs[regB])
	mul := lhs.Mul(lhs, rhs)
	i.setAndSkip(dst, uint64(mul.Rsh(mul, 64).Int64()))
}

// SetLessThanUnsigned set_lt_u φ′D = φA < φB
func (i *Instance) SetLessThanUnsigned(dst polkavm.Reg, regA, regB polkavm.Reg) {
	log.VM.Trace().Int64("gas", i.gasRemaining).Msgf("%d: set_lt_u %s=0x%x %s=0x%x %s=0x%x", i.instructionCounter, dst, i.regs[dst], regA, i.regs[regA], regB, i.regs[regB])
	i.setAndSkip(dst, bool2uint64(i.regs[regA] < i.regs[regB]))
}

// SetLessThanSigned set_lt_s φ′D = Z8(φA) < Z8(φB)
func (i *Instance) SetLessThanSigned(dst polkavm.Reg, regA, regB polkavm.Reg) {
	log.VM.Trace().Int64("gas", i.gasRemaining).Msgf("%d: set_lt_s %s=0x%x %s=0x%x %s=0x%x", i.instructionCounter, dst, i.regs[dst], regA, i.regs[regA], regB, i.regs[regB])
	i.setAndSkip(dst, bool2uint64(int32(i.regs[regA]) < int32(i.regs[regB])))
}

// CmovIfZero cmov_iz φ′D = φA if φB = 0 otherwise φD
func (i *Instance) CmovIfZero(dst polkavm.Reg, s, c polkavm.Reg) {
	log.VM.Trace().Int64("gas", i.gasRemaining).Msgf("%d: cmov_iz %s=0x%x %s=0x%x %s=0x%x", i.instructionCounter, dst, i.regs[dst], s, i.regs[s], c, i.regs[c])
	if i.regs[c] == 0 {
		i.regs[dst] = i.regs[s]
	}
	i.skip()
}

// CmovIfNotZero cmov_nz φ′D = φA if φB ≠ 0 otherwise φD
func (i *Instance) CmovIfNotZero(dst polkavm.Reg, s, c polkavm.Reg) {
	log.VM.Trace().Int64("gas", i.gasRemaining).Msgf("%d: cmov_nz %s=0x%x %s=0x%x %s=0x%x", i.instructionCounter, dst, i.regs[dst], s, i.regs[s], c, i.regs[c])
	if i.regs[c] != 0 {
		i.regs[dst] = i.regs[s]
	}
	i.skip()
}

// RotateLeft64 rot_l_64 ∀i ∈ N64 ∶ B8(φ′D)_{(i+φB) mod 64} = B8(φA)_i
func (i *Instance) RotateLeft64(dst polkavm.Reg, regA, regB polkavm.Reg) {
	log.VM.Trace().Int64("gas", i.gasRemaining).Msgf("%d: rot_l_64 %s=0x%x %s=0x%x %s=0x%x", i.instructionCounter, dst, i.regs[dst], regA, i.regs[regA], regB, i.regs[regB])
	i.setAndSkip(dst, bits.RotateLeft64(i.regs[regA], int(i.regs[regB])))
}

// RotateLeft32 rot_l_32 φ′D = X4(x) where x ∈ N2^32, ∀i ∈ N32 ∶ B4(x)_{(i+φB) mod 32} = B4(φA)_i
func (i *Instance) RotateLeft32(dst polkavm.Reg, regA, regB polkavm.Reg) {
	log.VM.Trace().Int64("gas", i.gasRemaining).Msgf("%d: rot_l_32 %s=0x%x %s=0x%x %s=0x%x", i.instructionCounter, dst, i.regs[dst], regA, i.regs[regA], regB, i.regs[regB])
	i.setAndSkip(dst, sext(uint64(bits.RotateLeft32(uint32(i.regs[regA]), int(i.regs[regB]))), 4))
}

// RotateRight64 rot_r_64 ∀i ∈ N64 ∶ B8(φ′D)_i = B8(φA)_{(i+φB ) mod 64}
func (i *Instance) RotateRight64(dst polkavm.Reg, regA, regB polkavm.Reg) {
	log.VM.Trace().Int64("gas", i.gasRemaining).Msgf("%d: rot_r_64 %s=0x%x %s=0x%x %s=0x%x", i.instructionCounter, dst, i.regs[dst], regA, i.regs[regA], regB, i.regs[regB])
	i.setAndSkip(dst, bits.RotateLeft64(i.regs[regA], -int(i.regs[regB])))
}

// RotateRight32 rot_r_32 φ′D = X4(x) where x ∈ N2^32, ∀i ∈ N32 ∶ B4(x)_i = B4(φA)_{(i+φB) mod 32}
func (i *Instance) RotateRight32(dst polkavm.Reg, regA, regB polkavm.Reg) {
	log.VM.Trace().Int64("gas", i.gasRemaining).Msgf("%d: rot_r_32 %s=0x%x %s=0x%x %s=0x%x", i.instructionCounter, dst, i.regs[dst], regA, i.regs[regA], regB, i.regs[regB])
	i.setAndSkip(dst, sext(uint64(bits.RotateLeft32(uint32(i.regs[regA]), -int(i.regs[regB]))), 4))
}

// AndInverted and_inv ∀i ∈ N64 ∶ B8(φ′D)_i = B8(φA)i ∧ ¬B8(φB)_i
func (i *Instance) AndInverted(dst polkavm.Reg, regA, regB polkavm.Reg) {
	log.VM.Trace().Int64("gas", i.gasRemaining).Msgf("%d: and_inv %s=0x%x %s=0x%x %s=0x%x", i.instructionCounter, dst, i.regs[dst], regA, i.regs[regA], regB, i.regs[regB])
	i.setAndSkip(dst, i.regs[regA]&^i.regs[regB])
}

// OrInverted or_inv ∀i ∈ N64 ∶ B8(φ′D)_i = B8(φA)i ∨ ¬B8(φB)_i
func (i *Instance) OrInverted(dst polkavm.Reg, regA, regB polkavm.Reg) {
	log.VM.Trace().Int64("gas", i.gasRemaining).Msgf("%d: or_inv %s=0x%x %s=0x%x %s=0x%x", i.instructionCounter, dst, i.regs[dst], regA, i.regs[regA], regB, i.regs[regB])
	i.setAndSkip(dst, i.regs[regA]|^i.regs[regB])
}

// Xnor xnor ∀i ∈ N64 ∶ B8(φ′D)_i = ¬(B8(φA)_i ⊕ B8(φB)_i)
func (i *Instance) Xnor(dst polkavm.Reg, regA, regB polkavm.Reg) {
	log.VM.Trace().Int64("gas", i.gasRemaining).Msgf("%d: xnor %s=0x%x %s=0x%x %s=0x%x", i.instructionCounter, dst, i.regs[dst], regA, i.regs[regA], regB, i.regs[regB])
	i.setAndSkip(dst, ^(i.regs[regA] ^ i.regs[regB]))
}

// Max max φ′D = Z−1_8(max(Z8(φA), Z8(φB)))
func (i *Instance) Max(dst polkavm.Reg, regA, regB polkavm.Reg) {
	log.VM.Trace().Int64("gas", i.gasRemaining).Msgf("%d: max %s=0x%x %s=0x%x %s=0x%x", i.instructionCounter, dst, i.regs[dst], regA, i.regs[regA], regB, i.regs[regB])
	i.setAndSkip(dst, uint64(max(int64(i.regs[regA]), int64(i.regs[regB]))))
}

// MaxUnsigned max_u φ′D = max(φA, φB)
func (i *Instance) MaxUnsigned(dst polkavm.Reg, regA, regB polkavm.Reg) {
	log.VM.Trace().Int64("gas", i.gasRemaining).Msgf("%d: max_u %s=0x%x %s=0x%x %s=0x%x", i.instructionCounter, dst, i.regs[dst], regA, i.regs[regA], regB, i.regs[regB])
	i.setAndSkip(dst, max(i.regs[regA], i.regs[regB]))
}

// Min min φ′D = Z8^-1(min(Z8(φA), Z8(φB)))
func (i *Instance) Min(dst polkavm.Reg, regA, regB polkavm.Reg) {
	log.VM.Trace().Int64("gas", i.gasRemaining).Msgf("%d: min %s=0x%x %s=0x%x %s=0x%x", i.instructionCounter, dst, i.regs[dst], regA, i.regs[regA], regB, i.regs[regB])
	i.setAndSkip(dst, uint64(min(int64(i.regs[regA]), int64(i.regs[regB]))))
}

// MinUnsigned min_u φ′D = min(φA, φB)
func (i *Instance) MinUnsigned(dst polkavm.Reg, regA, regB polkavm.Reg) {
	log.VM.Trace().Int64("gas", i.gasRemaining).Msgf("%d: min_u %s=0x%x %s=0x%x %s=0x%x", i.instructionCounter, dst, i.regs[dst], regA, i.regs[regA], regB, i.regs[regB])
	i.setAndSkip(dst, min(i.regs[regA], i.regs[regB]))
}

func bool2uint64(v bool) uint64 {
	if v {
		return 1
	}
	return 0
}

// smod (a Z, b Z) → Z a if b = 0 otherwise sgn(a)(|a| mod |b|) (eq. A.33 v0.7.0)
func smod64(a int64, b int64) int64 {
	if b == 0 {
		return a
	}
	if a < 0 {
		return -(abs64(a) % abs64(b))
	}
	return abs64(a) % abs64(b)
}

func abs64(v int64) int64 {
	mask := v >> 63
	return (v ^ mask) - mask
}

// smod (a Z, b Z) → Z a if b = 0 otherwise sgn(a)(|a| mod |b|) (eq. A.33 v0.7.0)
func smod32(a int32, b int32) int32 {
	if b == 0 {
		return a
	}
	if a < 0 {
		return -(abs32(a) % abs32(b))
	}
	return abs32(a) % abs32(b)
}

func abs32(v int32) int32 {
	mask := v >> 31
	return (v ^ mask) - mask
}
