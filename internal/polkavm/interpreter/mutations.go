package interpreter

import (
	"math"
	"math/big"
	"math/bits"

	"github.com/eigerco/strawberry/internal/polkavm"
)

// Trap trap ε = ☇
func (i *Instance) Trap() error {
	i.log.Debug().Msgf("%d: trap", i.instructionCounter)
	return polkavm.ErrPanicf("explicit trap")
}

// Fallthrough fallthrough
func (i *Instance) Fallthrough() {
	i.log.Debug().Msgf("%d: fallthrough", i.instructionCounter)
	i.skip()
}

// LoadImm64 load_imm_64 ω′A = νX
func (i *Instance) LoadImm64(dst polkavm.Reg, imm uint64) {
	i.log.Debug().Msgf("%d: load_imm_64 %s=0x%x v1=0x%x", i.instructionCounter, dst, i.regs[dst], imm)
	i.setAndSkip(dst, imm)
}

// StoreImmU8 store_imm_u8 μ′↺νX = νY mod 28
func (i *Instance) StoreImmU8(address uint64, value uint64) error {
	i.log.Debug().Msgf("%d: store_imm_u8 v1=0x%x v2=0x%x", i.instructionCounter, address, value)
	return i.store(address, uint8(value))
}

// StoreImmU16 store_imm_u16 μ′↺{νX...+2} = E2(νY mod 2^16)
func (i *Instance) StoreImmU16(address uint64, value uint64) error {
	i.log.Debug().Msgf("%d: store_imm_u16 v1=0x%x v2=0x%x", i.instructionCounter, address, value)
	return i.store(address, uint16(value))
}

// StoreImmU32 store_imm_u32 μ′↺{νX...+4} = E4(νY mod 2^32)
func (i *Instance) StoreImmU32(address uint64, value uint64) error {
	i.log.Debug().Msgf("%d: store_imm_u32 v1=0x%x v2=0x%x", i.instructionCounter, address, value)
	return i.store(address, uint32(value))
}

// StoreImmU64 store_imm_u64 μ′↺{νX...+8} = E8(νY)
func (i *Instance) StoreImmU64(address uint64, value uint64) error {
	i.log.Debug().Msgf("%d: store_imm_u64 v1=0x%x v2=0x%x", i.instructionCounter, address, value)
	return i.store(address, value)
}

// Jump jump branch(νX , ⊺)
func (i *Instance) Jump(target uint64) error {
	i.log.Debug().Msgf("%d: jump v1=0x%x", i.instructionCounter, target)
	return i.branch(true, target)
}

// JumpIndirect jump_ind djump((ωA + νX) mod 2^32)
func (i *Instance) JumpIndirect(base polkavm.Reg, offset uint64) error {
	i.log.Debug().Msgf("%d: jump_ind %s=0x%x v1=0x%x", i.instructionCounter, base, i.regs[base], offset)
	return i.djump(i.regs[base] + offset)
}

// LoadImm load_imm ω′A = νX
func (i *Instance) LoadImm(dst polkavm.Reg, imm uint64) {
	i.log.Debug().Msgf("%d: load_imm %s=0x%x v1=0x%x", i.instructionCounter, dst, i.regs[dst], imm)
	i.setAndSkip(dst, imm)
}

// LoadU8 load_u8 ω′A = μ↺_νX
func (i *Instance) LoadU8(dst polkavm.Reg, address uint64) error {
	i.log.Debug().Msgf("%d: load_u8 %s=0x%x v1=0x%x", i.instructionCounter, dst, i.regs[dst], address)
	slice := make([]byte, 1)
	if err := i.memory.Read(address, slice); err != nil {
		return err
	}
	i.setAndSkip(dst, uint64(slice[0]))
	return nil
}

// LoadI8 load_i8 ω′A = X1(μ↺_νX)
func (i *Instance) LoadI8(dst polkavm.Reg, address uint64) error {
	i.log.Debug().Msgf("%d: load_i8 %s=0x%x v1=0x%x", i.instructionCounter, dst, i.regs[dst], address)
	slice := make([]byte, 1)
	if err := i.memory.Read(address, slice); err != nil {
		return err
	}
	i.setAndSkip(dst, uint64(int8(slice[0])))
	return nil
}

// LoadU16 load_u16 ω′A = E−1_2 (μ↺_{νX...+2})
func (i *Instance) LoadU16(dst polkavm.Reg, address uint64) error {
	i.log.Debug().Msgf("%d: load_u16 %s=0x%x v1=0x%x", i.instructionCounter, dst, i.regs[dst], address)
	var v uint16
	if err := i.load(address, 2, &v); err != nil {
		return err
	}
	i.setAndSkip(dst, uint64(v))
	return nil
}

// LoadI16 load_i16 ω′A = X2(E−1_2 (μ↺_{νX...+2})
func (i *Instance) LoadI16(dst polkavm.Reg, address uint64) error {
	i.log.Debug().Msgf("%d: load_i16 %s=0x%x v1=0x%x", i.instructionCounter, dst, i.regs[dst], address)
	var v int16
	if err := i.load(address, 2, &v); err != nil {
		return err
	}
	i.setAndSkip(dst, uint64(v))
	return nil
}

// LoadU32 load_u32 ω′A = E−1_4 (μ↺_{νX...+4})
func (i *Instance) LoadU32(dst polkavm.Reg, address uint64) error {
	i.log.Debug().Msgf("%d: load_u32 %s=0x%x v1=0x%x", i.instructionCounter, dst, i.regs[dst], address)
	var v uint32
	if err := i.load(address, 4, &v); err != nil {
		return err
	}
	i.setAndSkip(dst, uint64(v))
	return nil
}

// LoadI32 load_i32 ω′A = X4(E−1_4(μ↺_{νX...+4}))
func (i *Instance) LoadI32(dst polkavm.Reg, address uint64) error {
	i.log.Debug().Msgf("%d: load_i32 %s=0x%x v1=0x%x", i.instructionCounter, dst, i.regs[dst], address)
	var v uint32
	if err := i.load(address, 4, &v); err != nil {
		return err
	}
	i.setAndSkip(dst, sext(uint64(v), 4))
	return nil
}

// LoadU64 load_u64 ω′A = E−1_8 (μ↺_{νX...+8})
func (i *Instance) LoadU64(dst polkavm.Reg, address uint64) error {
	i.log.Debug().Msgf("%d: load_u64 %s=0x%x v1=0x%x", i.instructionCounter, dst, i.regs[dst], address)
	var v uint64
	if err := i.load(address, 8, &v); err != nil {
		return err
	}
	i.setAndSkip(dst, v)
	return nil
}

// StoreU8 store_u8 μ′↺_νX = ωA mod 2^8
func (i *Instance) StoreU8(src polkavm.Reg, address uint64) error {
	i.log.Debug().Msgf("%d: store_u8 %s=0x%x v1=0x%x", i.instructionCounter, src, i.regs[src], address)
	return i.store(address, uint8(i.regs[src]))
}

// StoreU16 store_u16 μ′↺_{νX...+2} = E2(ωA mod 2^16)
func (i *Instance) StoreU16(src polkavm.Reg, address uint64) error {
	i.log.Debug().Msgf("%d: store_u16 %s=0x%x v1=0x%x", i.instructionCounter, src, i.regs[src], address)
	return i.store(address, uint16(i.regs[src]))
}

// StoreU32 store_u32 μ′↺_{νX...+4} = E4(ωA mod 2^32)
func (i *Instance) StoreU32(src polkavm.Reg, address uint64) error {
	i.log.Debug().Msgf("%d: store_u32 %s=0x%x v1=0x%x", i.instructionCounter, src, i.regs[src], address)
	return i.store(address, uint32(i.regs[src]))
}

// StoreU64 store_u64 μ′↺_{νX...+8} = E8(ωA)
func (i *Instance) StoreU64(src polkavm.Reg, address uint64) error {
	i.log.Debug().Msgf("%d: store_u64 %s=0x%x v1=0x%x", i.instructionCounter, src, i.regs[src], address)
	return i.store(address, i.regs[src])
}

// StoreImmIndirectU8 store_imm_ind_u8 μ′↺_{ωA+νX} = νY mod 2^8
func (i *Instance) StoreImmIndirectU8(base polkavm.Reg, offset uint64, value uint64) error {
	i.log.Debug().Msgf("%d: store_imm_ind_u8 %s=0x%x v1=0x%x v2=0x%x", i.instructionCounter, base, i.regs[base], offset, value)
	return i.store(i.regs[base]+offset, uint8(value))
}

// StoreImmIndirectU16 store_imm_ind_u16 μ′↺_{ωA+νX...+2} = E2(νY mod 2^16)
func (i *Instance) StoreImmIndirectU16(base polkavm.Reg, offset uint64, value uint64) error {
	i.log.Debug().Msgf("%d: store_imm_ind_u16 %s=0x%x v1=0x%x v2=0x%x", i.instructionCounter, base, i.regs[base], offset, value)
	return i.store(i.regs[base]+offset, uint16(value))
}

// StoreImmIndirectU32 store_imm_ind_u32 μ′↺_{ωA+νX...+4} = E4(νY mod 2^32)
func (i *Instance) StoreImmIndirectU32(base polkavm.Reg, offset uint64, value uint64) error {
	i.log.Debug().Msgf("%d: store_imm_ind_u32 %s=0x%x v1=0x%x v2=0x%x", i.instructionCounter, base, i.regs[base], offset, value)
	return i.store(i.regs[base]+offset, uint32(value))
}

// StoreImmIndirectU64 store_imm_ind_u64 μ′↺_{ωA+νX...+8} = E8(νY)
func (i *Instance) StoreImmIndirectU64(base polkavm.Reg, offset uint64, value uint64) error {
	i.log.Debug().Msgf("%d: store_imm_ind_u64 %s=0x%x v1=0x%x v2=0x%x", i.instructionCounter, base, i.regs[base], offset, value)
	return i.store(i.regs[base]+offset, value)
}

// LoadImmAndJump load_imm_jump branch(νY , ⊺), ω′A = νX
func (i *Instance) LoadImmAndJump(ra polkavm.Reg, value uint64, target uint64) error {
	i.log.Debug().Msgf("%d: load_imm_jump %s=0x%x v1=0x%x v2=0x%x", i.instructionCounter, ra, i.regs[ra], value, target)
	i.LoadImm(ra, value)
	return i.Jump(target)
}

// BranchEqImm branch_eq_imm branch(νY, ωA = νX)
func (i *Instance) BranchEqImm(regA polkavm.Reg, valueX uint64, target uint64) error {
	i.log.Debug().Msgf("%d: branch_eq_imm %s=0x%x v1=0x%x v2=0x%x", i.instructionCounter, regA, i.regs[regA], valueX, target)
	return i.branch(i.regs[regA] == valueX, target)
}

// BranchNotEqImm branch_ne_imm branch(νY, ωA ≠ νX)
func (i *Instance) BranchNotEqImm(regA polkavm.Reg, valueX uint64, target uint64) error {
	i.log.Debug().Msgf("%d: branch_ne_imm %s=0x%x v1=0x%x v2=0x%x", i.instructionCounter, regA, i.regs[regA], valueX, target)
	return i.branch(i.regs[regA] != valueX, target)
}

// BranchLessUnsignedImm branch_lt_u_imm branch(νY , ωA < νX)
func (i *Instance) BranchLessUnsignedImm(regA polkavm.Reg, valueX uint64, target uint64) error {
	i.log.Debug().Msgf("%d: branch_lt_u_imm %s=0x%x v1=0x%x v2=0x%x", i.instructionCounter, regA, i.regs[regA], valueX, target)
	return i.branch(i.regs[regA] < valueX, target)
}

// BranchLessOrEqualUnsignedImm branch_le_u_imm branch(νY, ωA ≤ νX)
func (i *Instance) BranchLessOrEqualUnsignedImm(regA polkavm.Reg, valueX uint64, target uint64) error {
	i.log.Debug().Msgf("%d: branch_le_u_imm %s=0x%x v1=0x%x v2=0x%x", i.instructionCounter, regA, i.regs[regA], valueX, target)
	return i.branch(i.regs[regA] <= valueX, target)
}

// BranchGreaterOrEqualUnsignedImm branch_ge_u_imm branch(νY, ωA ≥ νX)
func (i *Instance) BranchGreaterOrEqualUnsignedImm(regA polkavm.Reg, valueX uint64, target uint64) error {
	i.log.Debug().Msgf("%d: branch_ge_u_imm %s=0x%x v1=0x%x v2=0x%x", i.instructionCounter, regA, i.regs[regA], valueX, target)
	return i.branch(i.regs[regA] >= valueX, target)
}

// BranchGreaterUnsignedImm branch_gt_u_imm branch(νY, ωA > νX)
func (i *Instance) BranchGreaterUnsignedImm(regA polkavm.Reg, valueX uint64, target uint64) error {
	i.log.Debug().Msgf("%d: branch_gt_u_imm %s=0x%x v1=0x%x v2=0x%x", i.instructionCounter, regA, i.regs[regA], valueX, target)
	return i.branch(i.regs[regA] > valueX, target)
}

// BranchLessSignedImm branch_lt_s_imm branch(νY, Z8(ωA) < Z8(νX))
func (i *Instance) BranchLessSignedImm(regA polkavm.Reg, valueX uint64, target uint64) error {
	i.log.Debug().Msgf("%d: branch_lt_s_imm %s=0x%x v1=0x%x v2=0x%x", i.instructionCounter, regA, i.regs[regA], valueX, target)
	return i.branch(int64(i.regs[regA]) < int64(valueX), target)
}

// BranchLessOrEqualSignedImm branch_le_s_imm branch(νY , Z8(ωA) ≤ Z8(νX))
func (i *Instance) BranchLessOrEqualSignedImm(regA polkavm.Reg, valueX uint64, target uint64) error {
	i.log.Debug().Msgf("%d: branch_le_s_imm %s=0x%x v1=0x%x v2=0x%x", i.instructionCounter, regA, i.regs[regA], valueX, target)
	return i.branch(int64(i.regs[regA]) <= int64(valueX), target)
}

// BranchGreaterOrEqualSignedImm branch_ge_s_imm branch(νY, Z8(ωA) ≥ Z8(νX))
func (i *Instance) BranchGreaterOrEqualSignedImm(regA polkavm.Reg, valueX uint64, target uint64) error {
	i.log.Debug().Msgf("%d: branch_ge_s_imm %s=0x%x v1=0x%x v2=0x%x", i.instructionCounter, regA, i.regs[regA], valueX, target)
	return i.branch(int64(i.regs[regA]) >= int64(valueX), target)
}

// BranchGreaterSignedImm branch_gt_s_imm branch(νY, Z8(ωA) > Z8(νX))
func (i *Instance) BranchGreaterSignedImm(regA polkavm.Reg, valueX uint64, target uint64) error {
	i.log.Debug().Msgf("%d: branch_gt_s_imm %s=0x%x v1=0x%x v2=0x%x", i.instructionCounter, regA, i.regs[regA], valueX, target)
	return i.branch(int64(i.regs[regA]) > int64(valueX), target)
}

// MoveReg move_reg ω′D = ωA
func (i *Instance) MoveReg(dst polkavm.Reg, s polkavm.Reg) {
	i.log.Debug().Msgf("%d: move_reg %s=0x%x %s=0x%x", i.instructionCounter, dst, i.regs[dst], s, i.regs[s])
	i.setAndSkip(dst, i.regs[s])
}

// Sbrk sbrk ω′D ≡ min(x ∈ NR) ∶
// x ≥ h
// Nx⋅⋅⋅+ωA ~⊆ Vμ
// Nx⋅⋅⋅+ωA ⊆ V∗μ′
// The term h above refers to the beginning of the heap
func (i *Instance) Sbrk(dst polkavm.Reg, sizeReg polkavm.Reg) error {
	i.log.Debug().Msgf("%d: sbrk %s=0x%x %s=0x%x", i.instructionCounter, dst, i.regs[dst], sizeReg, i.regs[sizeReg])
	size := i.regs[sizeReg]
	heapTop, err := i.memory.Sbrk(size)
	if err != nil {
		return err
	}
	i.setAndSkip(dst, heapTop)
	return nil
}

// CountSetBits64 count_set_bits_64 ω′D = {63;i=0}∑ B8(ωA)_i
func (i *Instance) CountSetBits64(dst polkavm.Reg, s polkavm.Reg) {
	i.log.Debug().Msgf("%d: count_set_bits_64 %s=0x%x %s=0x%x", i.instructionCounter, dst, i.regs[dst], s, i.regs[s])
	i.setAndSkip(dst, uint64(bits.OnesCount64(i.regs[s])))
}

// CountSetBits32 count_set_bits_32 ω′D = {31;i=0}∑ B4(ωA mod 2^32)_i
func (i *Instance) CountSetBits32(dst polkavm.Reg, s polkavm.Reg) {
	i.log.Debug().Msgf("%d: count_set_bits_32 %s=0x%x %s=0x%x", i.instructionCounter, dst, i.regs[dst], s, i.regs[s])
	i.setAndSkip(dst, uint64(bits.OnesCount32(uint32(i.regs[s]))))
}

// LeadingZeroBits64 leading_zero_bits_64 ω′D = max(n ∈ N65) where {i<n;i=0}∑ B8(ωA)_i = 0
func (i *Instance) LeadingZeroBits64(dst polkavm.Reg, s polkavm.Reg) {
	i.log.Debug().Msgf("%d: leading_zero_bits_64 %s=0x%x %s=0x%x", i.instructionCounter, dst, i.regs[dst], s, i.regs[s])
	i.setAndSkip(dst, uint64(bits.LeadingZeros64(i.regs[s])))
}

// LeadingZeroBits32 leading_zero_bits_32 ω′D = max(n ∈ N33) where {i<n;i=0}∑ B4(ωA mod 232)_i = 0
func (i *Instance) LeadingZeroBits32(dst polkavm.Reg, s polkavm.Reg) {
	i.log.Debug().Msgf("%d: leading_zero_bits_32 %s=0x%x %s=0x%x", i.instructionCounter, dst, i.regs[dst], s, i.regs[s])
	i.setAndSkip(dst, uint64(bits.LeadingZeros32(uint32(i.regs[s]))))
}

// TrailingZeroBits64 trailing_zero_bits_64 ω′D = max(n ∈ N65) where {i<n;i=0}∑ B8(ωA)_63−i = 0
func (i *Instance) TrailingZeroBits64(dst polkavm.Reg, s polkavm.Reg) {
	i.log.Debug().Msgf("%d: trailing_zero_bits_64 %s=0x%x %s=0x%x", i.instructionCounter, dst, i.regs[dst], s, i.regs[s])
	i.setAndSkip(dst, uint64(bits.TrailingZeros64(i.regs[s])))
}

// TrailingZeroBits32 trailing_zero_bits_32 ω′D = max(n ∈ N33) where {i<n;i=0}∑ B4(ωA mod 232)_31−i = 0
func (i *Instance) TrailingZeroBits32(dst polkavm.Reg, s polkavm.Reg) {
	i.log.Debug().Msgf("%d: trailing_zero_bits_32 %s=0x%x %s=0x%x", i.instructionCounter, dst, i.regs[dst], s, i.regs[s])
	i.setAndSkip(dst, uint64(bits.TrailingZeros32(uint32(i.regs[s]))))
}

// SignExtend8 sign_extend_8 ω′D = Z−1_8(Z_1(ωA mod 2^8))
func (i *Instance) SignExtend8(dst polkavm.Reg, s polkavm.Reg) {
	i.log.Debug().Msgf("%d: sign_extend_8 %s=0x%x %s=0x%x", i.instructionCounter, dst, i.regs[dst], s, i.regs[s])
	i.setAndSkip(dst, uint64(int8(uint8(i.regs[s]))))
}

// SignExtend16 sign_extend_16 ω′D = Z−1_8(Z_2(ωA mod 2^16))
func (i *Instance) SignExtend16(dst polkavm.Reg, s polkavm.Reg) {
	i.log.Debug().Msgf("%d: sign_extend_16 %s=0x%x %s=0x%x", i.instructionCounter, dst, i.regs[dst], s, i.regs[s])
	i.setAndSkip(dst, uint64(int16(uint16(i.regs[s]))))
}

// ZeroExtend16 zero_extend_16 ω′D = ωA mod 2^16
func (i *Instance) ZeroExtend16(dst polkavm.Reg, s polkavm.Reg) {
	i.log.Debug().Msgf("%d: zero_extend_16 %s=0x%x %s=0x%x", i.instructionCounter, dst, i.regs[dst], s, i.regs[s])
	i.setAndSkip(dst, uint64(uint16(i.regs[s])))
}

// ReverseBytes reverse_bytes ∀i ∈ N8 ∶ E8(ω′D)i = E8(ωA)_7−i
func (i *Instance) ReverseBytes(dst polkavm.Reg, s polkavm.Reg) {
	i.log.Debug().Msgf("%d: reverse_bytes %s=0x%x %s=0x%x", i.instructionCounter, dst, i.regs[dst], s, i.regs[s])
	i.setAndSkip(dst, bits.ReverseBytes64(i.regs[s]))
}

// StoreIndirectU8 store_ind_u8 μ′↺_{ωB+νX} = ωA mod 2^8
func (i *Instance) StoreIndirectU8(src polkavm.Reg, base polkavm.Reg, offset uint64) error {
	i.log.Debug().Msgf("%d: store_ind_u8 %s=0x%x %s=0x%x v1=0x%x", i.instructionCounter, src, i.regs[src], base, i.regs[base], offset)
	return i.store(i.regs[base]+offset, uint8(i.regs[src]))
}

// StoreIndirectU16 store_ind_u16 μ′↺_{ωB+νX...+2} = E2(ωA mod 2^16)
func (i *Instance) StoreIndirectU16(src polkavm.Reg, base polkavm.Reg, offset uint64) error {
	i.log.Debug().Msgf("%d: store_ind_u16 %s=0x%x %s=0x%x v1=0x%x", i.instructionCounter, src, i.regs[src], base, i.regs[base], offset)
	return i.store(i.regs[base]+offset, uint16(i.regs[src]))
}

// StoreIndirectU32 store_ind_u32 μ′↺_{ωB+νX...+4} = E4(ωA mod 2^32)
func (i *Instance) StoreIndirectU32(src polkavm.Reg, base polkavm.Reg, offset uint64) error {
	i.log.Debug().Msgf("%d: store_ind_u32 %s=0x%x %s=0x%x v1=0x%x", i.instructionCounter, src, i.regs[src], base, i.regs[base], offset)
	return i.store(i.regs[base]+offset, uint32(i.regs[src]))
}

// StoreIndirectU64 store_ind_u64 μ′↺_{ωB+νX...+8} = E8(ωA)
func (i *Instance) StoreIndirectU64(src polkavm.Reg, base polkavm.Reg, offset uint64) error {
	i.log.Debug().Msgf("%d: store_ind_u64 %s=0x%x %s=0x%x v1=0x%x", i.instructionCounter, src, i.regs[src], base, i.regs[base], offset)
	return i.store(i.regs[base]+offset, i.regs[src])
}

// LoadIndirectU8 load_ind_u8 ω′A = μ↺_{ωB+νX}
func (i *Instance) LoadIndirectU8(dst polkavm.Reg, base polkavm.Reg, offset uint64) error {
	i.log.Debug().Msgf("%d: load_ind_u8 %s=0x%x %s=0x%x v1=0x%x", i.instructionCounter, dst, i.regs[dst], base, i.regs[base], offset)
	slice := make([]byte, 1)
	if err := i.memory.Read(i.regs[base]+offset, slice); err != nil {
		return err
	}
	i.setAndSkip(dst, uint64(slice[0]))
	return nil
}

// LoadIndirectI8 load_ind_i8 ω′A = Z−1_8(Z1(μ↺_{ωB+νX}))
func (i *Instance) LoadIndirectI8(dst polkavm.Reg, base polkavm.Reg, offset uint64) error {
	i.log.Debug().Msgf("%d: load_ind_i8 %s=0x%x %s=0x%x v1=0x%x", i.instructionCounter, dst, i.regs[dst], base, i.regs[base], offset)
	slice := make([]byte, 1)
	if err := i.memory.Read(i.regs[base]+offset, slice); err != nil {
		return err
	}
	i.setAndSkip(dst, uint64(int8(slice[0])))
	return nil
}

// LoadIndirectU16 load_ind_u16 ω′A = E−1_2 (μ↺_{ωB+νX...+2})
func (i *Instance) LoadIndirectU16(dst polkavm.Reg, base polkavm.Reg, offset uint64) error {
	i.log.Debug().Msgf("%d: load_ind_u16 %s=0x%x %s=0x%x v1=0x%x", i.instructionCounter, dst, i.regs[dst], base, i.regs[base], offset)
	var v uint16
	if err := i.load(i.regs[base]+offset, 2, &v); err != nil {
		return err
	}
	i.setAndSkip(dst, uint64(v))
	return nil
}

// LoadIndirectI16 load_ind_i16 ω′A = Z−1_8(Z2(E−1_2(μ↺_{ωB+νX...+2})))
func (i *Instance) LoadIndirectI16(dst polkavm.Reg, base polkavm.Reg, offset uint64) error {
	i.log.Debug().Msgf("%d: load_ind_i16 %s=0x%x %s=0x%x v1=0x%x", i.instructionCounter, dst, i.regs[dst], base, i.regs[base], offset)
	var v int16
	if err := i.load(i.regs[base]+offset, 2, &v); err != nil {
		return err
	}
	i.setAndSkip(dst, uint64(v))
	return nil
}

// LoadIndirectU32 load_ind_u32 ω′A = E−1_4(μ↺_{ωB+νX...+4})
func (i *Instance) LoadIndirectU32(dst polkavm.Reg, base polkavm.Reg, offset uint64) error {
	i.log.Debug().Msgf("%d: load_ind_u32 %s=0x%x %s=0x%x v1=0x%x", i.instructionCounter, dst, i.regs[dst], base, i.regs[base], offset)
	var v uint32
	if err := i.load(i.regs[base]+offset, 4, &v); err != nil {
		return err
	}
	i.setAndSkip(dst, uint64(v))
	return nil
}

// LoadIndirectI32 load_ind_i32 ω′A = Z−1_8(Z4(E−1_4(μ↺_{ωB+νX...+4})))
func (i *Instance) LoadIndirectI32(dst polkavm.Reg, base polkavm.Reg, offset uint64) error {
	i.log.Debug().Msgf("%d: load_ind_i32 %s=0x%x %s=0x%x v1=0x%x", i.instructionCounter, dst, i.regs[dst], base, i.regs[base], offset)
	var v int32
	if err := i.load(i.regs[base]+offset, 4, &v); err != nil {
		return err
	}
	i.setAndSkip(dst, uint64(v))
	return nil
}

// LoadIndirectU64 load_ind_u64 ω′A = E−1_8(μ↺_{ωB+νX...+8})
func (i *Instance) LoadIndirectU64(dst polkavm.Reg, base polkavm.Reg, offset uint64) error {
	i.log.Debug().Msgf("%d: load_ind_u64 %s=0x%x %s=0x%x v1=0x%x", i.instructionCounter, dst, i.regs[dst], base, i.regs[base], offset)
	var v uint64
	if err := i.load(i.regs[base]+offset, 8, &v); err != nil {
		return err
	}
	i.setAndSkip(dst, v)
	return nil
}

// AddImm32 add_imm_32 ω′A = X4((ωB + νX) mod 2^32)
func (i *Instance) AddImm32(dst polkavm.Reg, regA polkavm.Reg, value uint64) {
	i.log.Debug().Msgf("%d: add_imm_32 %s=0x%x %s=0x%x v1=0x%x", i.instructionCounter, dst, i.regs[dst], regA, i.regs[regA], value)
	i.setAndSkip(dst, sext(uint64(uint32(i.regs[regA]+value)), 4))
}

// AndImm and_imm ∀i ∈ N64 ∶ B8(ω′A)_i = B8(ωB)_i ∧ B8(νX)_i
func (i *Instance) AndImm(dst polkavm.Reg, regA polkavm.Reg, value uint64) {
	i.log.Debug().Msgf("%d: and_imm %s=0x%x %s=0x%x v1=0x%x", i.instructionCounter, dst, i.regs[dst], regA, i.regs[regA], value)
	i.setAndSkip(dst, (i.regs[regA])&value)
}

// XorImm xor_imm ∀i ∈ N64 ∶ B8(ω′A)i = B8(ωB)_i ⊕ B8(νX)_i
func (i *Instance) XorImm(dst polkavm.Reg, regA polkavm.Reg, value uint64) {
	i.log.Debug().Msgf("%d: xor_imm %s=0x%x %s=0x%x v1=0x%x", i.instructionCounter, dst, i.regs[dst], regA, i.regs[regA], value)
	i.setAndSkip(dst, (i.regs[regA])^value)
}

// OrImm or_imm ∀i ∈ N64 ∶ B8(ω′A)i = B8(ωB)_i ∨ B8(νX)_i
func (i *Instance) OrImm(dst polkavm.Reg, regA polkavm.Reg, value uint64) {
	i.log.Debug().Msgf("%d: or_imm %s=0x%x %s=0x%x v1=0x%x", i.instructionCounter, dst, i.regs[dst], regA, i.regs[regA], value)
	i.setAndSkip(dst, (i.regs[regA])|value)
}

// MulImm32 mul_imm_32 ω′A = X4((ωB ⋅ νX) mod 2^32)
func (i *Instance) MulImm32(dst polkavm.Reg, regA polkavm.Reg, value uint64) {
	i.log.Debug().Msgf("%d: mul_imm_32 %s=0x%x %s=0x%x v1=0x%x", i.instructionCounter, dst, i.regs[dst], regA, i.regs[regA], value)
	i.setAndSkip(dst, sext(uint64(uint32(i.regs[regA]*value)), 4))
}

// SetLessThanUnsignedImm set_lt_u_imm ω′A = ωB < νX
func (i *Instance) SetLessThanUnsignedImm(dst polkavm.Reg, regA polkavm.Reg, value uint64) {
	i.log.Debug().Msgf("%d: set_lt_u_imm %s=0x%x %s=0x%x v1=0x%x", i.instructionCounter, dst, i.regs[dst], regA, i.regs[regA], value)
	i.setAndSkip(dst, bool2uint64((i.regs[regA]) < value))
}

// SetLessThanSignedImm set_lt_s_imm ω′A = Z8(ωB) < Z8(νX)
func (i *Instance) SetLessThanSignedImm(dst polkavm.Reg, regA polkavm.Reg, value uint64) {
	i.log.Debug().Msgf("%d: set_lt_s_imm %s=0x%x %s=0x%x v1=0x%x", i.instructionCounter, dst, i.regs[dst], regA, i.regs[regA], value)
	i.setAndSkip(dst, bool2uint64(int64(i.regs[regA]) < int64(value)))
}

// ShiftLogicalLeftImm32 shlo_l_imm_32 ω′A = X4((ωB ⋅ 2^νX mod 32) mod 2^32)
func (i *Instance) ShiftLogicalLeftImm32(dst polkavm.Reg, regA polkavm.Reg, value uint64) {
	i.log.Debug().Msgf("%d: shlo_l_imm_32 %s=0x%x %s=0x%x v1=0x%x", i.instructionCounter, dst, i.regs[dst], regA, i.regs[regA], value)
	i.setAndSkip(dst, sext(uint64(uint32(i.regs[regA])<<value), 4))
}

// ShiftLogicalRightImm32 shlo_r_imm_32 ω′A = X4(⌊ ωB mod 2^32 ÷ 2^νX mod 32 ⌋)
func (i *Instance) ShiftLogicalRightImm32(dst polkavm.Reg, regA polkavm.Reg, value uint64) {
	i.log.Debug().Msgf("%d: shlo_r_imm_32 %s=0x%x %s=0x%x v1=0x%x", i.instructionCounter, dst, i.regs[dst], regA, i.regs[regA], value)
	i.setAndSkip(dst, sext(uint64(uint32(i.regs[regA])>>value), 4))
}

// ShiftArithmeticRightImm32 shar_r_imm_32 ω′A = Z−1_8(⌊ Z4(ωB mod 2^32) ÷ 2^νX mod 32 ⌋)
func (i *Instance) ShiftArithmeticRightImm32(dst polkavm.Reg, regA polkavm.Reg, value uint64) {
	i.log.Debug().Msgf("%d: shar_r_imm_32 %s=0x%x %s=0x%x v1=0x%x", i.instructionCounter, dst, i.regs[dst], regA, i.regs[regA], value)
	i.setAndSkip(dst, uint64(int32(uint32(i.regs[regA]))>>value))
}

// NegateAndAddImm32 neg_add_imm_32 ω′A = X4((νX + 2^32 − ωB) mod 2^32)
func (i *Instance) NegateAndAddImm32(dst polkavm.Reg, regA polkavm.Reg, value uint64) {
	i.log.Debug().Msgf("%d: neg_add_imm_32 %s=0x%x %s=0x%x v1=0x%x", i.instructionCounter, dst, i.regs[dst], regA, i.regs[regA], value)
	i.setAndSkip(dst, sext(uint64(uint32(value-i.regs[regA])), 4))
}

// SetGreaterThanUnsignedImm set_gt_u_imm ω′A = ωB > νX
func (i *Instance) SetGreaterThanUnsignedImm(dst polkavm.Reg, regA polkavm.Reg, value uint64) {
	i.log.Debug().Msgf("%d: set_gt_u_imm %s=0x%x %s=0x%x v1=0x%x", i.instructionCounter, dst, i.regs[dst], regA, i.regs[regA], value)
	i.setAndSkip(dst, bool2uint64(i.regs[regA] > value))
}

// SetGreaterThanSignedImm set_gt_s_imm ω′A = Z8(ωB) > Z8(νX)
func (i *Instance) SetGreaterThanSignedImm(dst polkavm.Reg, regA polkavm.Reg, value uint64) {
	i.log.Debug().Msgf("%d: set_gt_s_imm %s=0x%x %s=0x%x v1=0x%x", i.instructionCounter, dst, i.regs[dst], regA, i.regs[regA], value)
	i.setAndSkip(dst, bool2uint64(int64(i.regs[regA]) > int64(value)))
}

// ShiftLogicalLeftImmAlt32 shlo_l_imm_alt_32 ω′A = X4((νX ⋅ 2ωB mod 32) mod 2^32)
func (i *Instance) ShiftLogicalLeftImmAlt32(dst polkavm.Reg, regB polkavm.Reg, value uint64) {
	i.log.Debug().Msgf("%d: shlo_l_imm_alt_32 %s=0x%x %s=0x%x v1=0x%x", i.instructionCounter, dst, i.regs[dst], regB, i.regs[regB], value)
	i.setAndSkip(dst, sext(uint64(uint32(value<<i.regs[regB])), 4))
}

// ShiftLogicalRightImmAlt32 shlo_r_imm_alt_32 ω′A = X4(⌊ νX mod 2^32 ÷ 2^ωB mod 32 ⌋)
func (i *Instance) ShiftLogicalRightImmAlt32(dst polkavm.Reg, regB polkavm.Reg, value uint64) {
	i.log.Debug().Msgf("%d: shlo_r_imm_alt_32 %s=0x%x %s=0x%x v1=0x%x", i.instructionCounter, dst, i.regs[dst], regB, i.regs[regB], value)
	i.setAndSkip(dst, sext(uint64(uint32(value)>>uint32(i.regs[regB])), 4))
}

// ShiftArithmeticRightImmAlt32 shar_r_imm_alt_32 ω′A = Z−1_8(⌊ Z4(νX mod 2^32) ÷ 2ωB mod 32 ⌋)
func (i *Instance) ShiftArithmeticRightImmAlt32(dst polkavm.Reg, regB polkavm.Reg, value uint64) {
	i.log.Debug().Msgf("%d: shar_r_imm_alt_32 %s=0x%x %s=0x%x v1=0x%x", i.instructionCounter, dst, i.regs[dst], regB, i.regs[regB], value)
	i.setAndSkip(dst, uint64(int32(uint32(value))>>uint32(i.regs[regB])))
}

// CmovIfZeroImm cmov_iz_imm ω′A = νX if ωB = 0 otherwise ωA
func (i *Instance) CmovIfZeroImm(dst polkavm.Reg, c polkavm.Reg, s uint64) {
	i.log.Debug().Msgf("%d: cmov_iz_imm %s=0x%x %s=0x%x v1=0x%x", i.instructionCounter, dst, i.regs[dst], c, i.regs[c], s)
	if i.regs[c] == 0 {
		i.regs[dst] = s
	}
	i.skip()
}

// CmovIfNotZeroImm cmov_nz_imm ω′A = νX if ωB ≠ 0 otherwise ωA
func (i *Instance) CmovIfNotZeroImm(dst polkavm.Reg, c polkavm.Reg, s uint64) {
	i.log.Debug().Msgf("%d: cmov_nz_imm %s=0x%x %s=0x%x v1=0x%x", i.instructionCounter, dst, i.regs[dst], c, i.regs[c], s)
	if i.regs[c] != 0 {
		i.regs[dst] = s
	}

	i.skip()
}

// AddImm64 add_imm_64 ω′A = (ωB + νX) mod 2^64
func (i *Instance) AddImm64(dst polkavm.Reg, regA polkavm.Reg, value uint64) {
	i.log.Debug().Msgf("%d: add_imm_64 %s=0x%x %s=0x%x v1=0x%x", i.instructionCounter, dst, i.regs[dst], regA, i.regs[regA], value)
	i.setAndSkip(dst, i.regs[regA]+value)
}

// MulImm64 mul_imm_64 ω′A = (ωB ⋅ νX) mod 2^64
func (i *Instance) MulImm64(dst polkavm.Reg, regA polkavm.Reg, value uint64) {
	i.log.Debug().Msgf("%d: mul_imm_64 %s=0x%x %s=0x%x v1=0x%x", i.instructionCounter, dst, i.regs[dst], regA, i.regs[regA], value)
	i.setAndSkip(dst, i.regs[regA]*value)
}

// ShiftLogicalLeftImm64 shlo_l_imm_64 ω′A = X8((ωB ⋅ 2^νX mod 64) mod 2^64)
func (i *Instance) ShiftLogicalLeftImm64(dst polkavm.Reg, regA polkavm.Reg, value uint64) {
	i.log.Debug().Msgf("%d: shlo_l_imm_64 %s=0x%x %s=0x%x v1=0x%x", i.instructionCounter, dst, i.regs[dst], regA, i.regs[regA], value)
	i.setAndSkip(dst, sext(i.regs[regA]<<value, 8))
}

// ShiftLogicalRightImm64 shlo_r_imm_64 ω′A = X8(⌊ ωB ÷ 2^νX mod 64 ⌋)
func (i *Instance) ShiftLogicalRightImm64(dst polkavm.Reg, regA polkavm.Reg, value uint64) {
	i.log.Debug().Msgf("%d: shlo_r_imm_64 %s=0x%x %s=0x%x v1=0x%x", i.instructionCounter, dst, i.regs[dst], regA, i.regs[regA], value)
	i.setAndSkip(dst, sext(i.regs[regA]>>value, 8))
}

// ShiftArithmeticRightImm64 shar_r_imm_64 ω′A = Z−1_8(⌊ Z8(ωB) ÷ 2νX mod 64 ⌋)
func (i *Instance) ShiftArithmeticRightImm64(dst polkavm.Reg, regA polkavm.Reg, value uint64) {
	i.log.Debug().Msgf("%d: shar_r_imm_64 %s=0x%x %s=0x%x v1=0x%x", i.instructionCounter, dst, i.regs[dst], regA, i.regs[regA], value)
	i.setAndSkip(dst, uint64(int64(i.regs[regA])>>value))
}

// NegateAndAddImm64 neg_add_imm_64 ω′A = (νX + 2^64 − ωB) mod 2^64
func (i *Instance) NegateAndAddImm64(dst polkavm.Reg, regA polkavm.Reg, value uint64) {
	i.log.Debug().Msgf("%d: neg_add_imm_64 %s=0x%x %s=0x%x v1=0x%x", i.instructionCounter, dst, i.regs[dst], regA, i.regs[regA], value)
	i.setAndSkip(dst, value-i.regs[regA])
}

// ShiftLogicalLeftImmAlt64 shlo_l_imm_alt_64 ω′A = (νX ⋅ 2ωB mod 64) mod 2^64
func (i *Instance) ShiftLogicalLeftImmAlt64(dst polkavm.Reg, regB polkavm.Reg, value uint64) {
	i.log.Debug().Msgf("%d: shlo_l_imm_alt_64 %s=0x%x %s=0x%x v1=0x%x", i.instructionCounter, dst, i.regs[dst], regB, i.regs[regB], value)
	i.setAndSkip(dst, value<<i.regs[regB])
}

// ShiftLogicalRightImmAlt64 shlo_r_imm_alt_64 ω′A = ⌊ νX ÷ 2^ωB mod 64 ⌋
func (i *Instance) ShiftLogicalRightImmAlt64(dst polkavm.Reg, regB polkavm.Reg, value uint64) {
	i.log.Debug().Msgf("%d: shlo_r_imm_alt_64 %s=0x%x %s=0x%x v1=0x%x", i.instructionCounter, dst, i.regs[dst], regB, i.regs[regB], value)
	i.setAndSkip(dst, value>>i.regs[regB])
}

// ShiftArithmeticRightImmAlt64 shar_r_imm_alt_64 ω′A = Z−1_8(⌊ Z8(νX) ÷ 2ωB mod 64 ⌋)
func (i *Instance) ShiftArithmeticRightImmAlt64(dst polkavm.Reg, regB polkavm.Reg, value uint64) {
	i.log.Debug().Msgf("%d: shar_r_imm_alt_64 %s=0x%x %s=0x%x v1=0x%x", i.instructionCounter, dst, i.regs[dst], regB, i.regs[regB], value)
	i.setAndSkip(dst, uint64(int32(value)>>i.regs[regB]))
}

// RotateRight64Imm rot_r_64_imm ∀i ∈ N64 ∶ B8(ω′A)_i = B8(ωB)_{(i+νX) mod 64}
func (i *Instance) RotateRight64Imm(dst polkavm.Reg, regA polkavm.Reg, value uint64) {
	i.log.Debug().Msgf("%d: rot_r_64_imm %s=0x%x %s=0x%x v1=0x%x", i.instructionCounter, dst, i.regs[dst], regA, i.regs[regA], value)
	i.setAndSkip(dst, bits.RotateLeft64(i.regs[regA], -int(value)))
}

// RotateRight64ImmAlt rot_r_64_imm_alt ∀i ∈ N64 ∶ B8(ω′A)i = B8(νX)_{(i+ωB) mod 64}
func (i *Instance) RotateRight64ImmAlt(dst polkavm.Reg, regA polkavm.Reg, value uint64) {
	i.log.Debug().Msgf("%d: rot_r_64_imm_alt %s=0x%x %s=0x%x v1=0x%x", i.instructionCounter, dst, i.regs[dst], regA, i.regs[regA], value)
	i.setAndSkip(dst, bits.RotateLeft64(value, -int(i.regs[regA])))
}

// RotateRight32Imm rot_r_32_imm ω′A = X4(x) where x ∈ N2^32, ∀i ∈ N32 ∶ B4(x)_i = B4(ωB)_{(i+νX ) mod 32}
func (i *Instance) RotateRight32Imm(dst polkavm.Reg, regA polkavm.Reg, value uint64) {
	i.log.Debug().Msgf("%d: rot_r_32_imm %s=0x%x %s=0x%x v1=0x%x", i.instructionCounter, dst, i.regs[dst], regA, i.regs[regA], value)
	i.setAndSkip(dst, sext(uint64(bits.RotateLeft32(uint32(i.regs[regA]), -int(value))), 4))
}

// RotateRight32ImmAlt rot_r_32_imm_alt ω′A = X4(x) where x ∈ N2^32, ∀i ∈ N32 ∶ B4(x)_i = B4(νX)_{(i+ωB) mod 32}
func (i *Instance) RotateRight32ImmAlt(dst polkavm.Reg, regA polkavm.Reg, value uint64) {
	i.log.Debug().Msgf("%d: rot_r_32_imm_alt %s=0x%x %s=0x%x v1=0x%x", i.instructionCounter, dst, i.regs[dst], regA, i.regs[regA], value)
	i.setAndSkip(dst, sext(uint64(bits.RotateLeft32(uint32(value), -int(uint32(i.regs[regA])))), 4))
}

// BranchEq branch_eq branch(νX, ωA = ωB)
func (i *Instance) BranchEq(regA polkavm.Reg, regB polkavm.Reg, target uint64) error {
	i.log.Debug().Msgf("%d: branch_eq %s=0x%x %s=0x%x v1=0x%x", i.instructionCounter, regA, i.regs[regA], regB, i.regs[regB], target)
	return i.branch(i.regs[regA] == i.regs[regB], target)
}

// BranchNotEq branch_ne branch(νX, ωA ≠ ωB)
func (i *Instance) BranchNotEq(regA polkavm.Reg, regB polkavm.Reg, target uint64) error {
	i.log.Debug().Msgf("%d: branch_ne %s=0x%x %s=0x%x v1=0x%x", i.instructionCounter, regA, i.regs[regA], regB, i.regs[regB], target)
	return i.branch(i.regs[regA] != i.regs[regB], target)
}

// BranchLessUnsigned branch_lt_u branch(νX, ωA < ωB)
func (i *Instance) BranchLessUnsigned(regA polkavm.Reg, regB polkavm.Reg, target uint64) error {
	i.log.Debug().Msgf("%d: branch_lt_u %s=0x%x %s=0x%x v1=0x%x", i.instructionCounter, regA, i.regs[regA], regB, i.regs[regB], target)
	return i.branch(i.regs[regA] < i.regs[regB], target)
}

// BranchLessSigned branch_lt_s branch(νX, Z8(ωA) < Z8(ωB))
func (i *Instance) BranchLessSigned(regA polkavm.Reg, regB polkavm.Reg, target uint64) error {
	i.log.Debug().Msgf("%d: branch_lt_s %s=0x%x %s=0x%x v1=0x%x", i.instructionCounter, regA, i.regs[regA], regB, i.regs[regB], target)
	return i.branch(int64(i.regs[regA]) < int64(i.regs[regB]), target)
}

// BranchGreaterOrEqualUnsigned branch_ge_u branch(νX, ωA ≥ ωB)
func (i *Instance) BranchGreaterOrEqualUnsigned(regA polkavm.Reg, regB polkavm.Reg, target uint64) error {
	i.log.Debug().Msgf("%d: branch_ge_u %s=0x%x %s=0x%x v1=0x%x", i.instructionCounter, regA, i.regs[regA], regB, i.regs[regB], target)
	return i.branch(i.regs[regA] >= i.regs[regB], target)
}

// BranchGreaterOrEqualSigned branch_ge_s branch(νX, Z8(ωA) ≥ Z8(ωB))
func (i *Instance) BranchGreaterOrEqualSigned(regA polkavm.Reg, regB polkavm.Reg, target uint64) error {
	i.log.Debug().Msgf("%d: branch_ge_s %s=0x%x %s=0x%x v1=0x%x", i.instructionCounter, regA, i.regs[regA], regB, i.regs[regB], target)
	return i.branch(int64(i.regs[regA]) >= int64(i.regs[regB]), target)
}

// LoadImmAndJumpIndirect load_imm_jump_ind djump((ωB + νY) mod 232), ω′A = νX
func (i *Instance) LoadImmAndJumpIndirect(regA polkavm.Reg, base polkavm.Reg, value, offset uint64) error {
	i.log.Debug().Msgf("%d: load_imm_jump_ind %s=0x%x %s=0x%x v1=0x%x v2=0x%x", i.instructionCounter, regA, i.regs[regA], base, i.regs[base], value, offset)
	target := i.regs[base] + offset
	i.regs[regA] = value
	return i.djump(target)
}

// Add32 add_32 ω′D = X4((ωA + ωB) mod 2^32)
func (i *Instance) Add32(dst polkavm.Reg, regA, regB polkavm.Reg) {
	i.log.Debug().Msgf("%d: add_32 %s=0x%x %s=0x%x %s=0x%x", i.instructionCounter, dst, i.regs[dst], regA, i.regs[regA], regB, i.regs[regB])
	i.setAndSkip(dst, sext(uint64(uint32(i.regs[regA]+i.regs[regB])), 4))
}

// Sub32 sub_32 ω′D = X4((ωA + 2^32 − (ωB mod 2^32)) mod 2^32)
func (i *Instance) Sub32(dst polkavm.Reg, regA, regB polkavm.Reg) {
	i.log.Debug().Msgf("%d: sub_32 %s=0x%x %s=0x%x %s=0x%x", i.instructionCounter, dst, i.regs[dst], regA, i.regs[regA], regB, i.regs[regB])
	i.setAndSkip(dst, sext(uint64(uint32(i.regs[regA]-i.regs[regB])), 4))
}

// Mul32 mul_32 ω′D = X4((ωA ⋅ ωB) mod 2^32)
func (i *Instance) Mul32(dst polkavm.Reg, regA, regB polkavm.Reg) {
	i.log.Debug().Msgf("%d: mul_32 %s=0x%x %s=0x%x %s=0x%x", i.instructionCounter, dst, i.regs[dst], regA, i.regs[regA], regB, i.regs[regB])
	i.setAndSkip(dst, sext(uint64(uint32(i.regs[regA]*i.regs[regB])), 4))
}

// DivUnsigned32 div_u_32 ω′D = 2^64 − 1 if ωB mod 2^32 = 0 otherwise X4(⌊ (ωA mod 2^32) ÷ (ωB mod 2^32) ⌋)
func (i *Instance) DivUnsigned32(dst polkavm.Reg, regA, regB polkavm.Reg) {
	i.log.Debug().Msgf("%d: div_u_32 %s=0x%x %s=0x%x %s=0x%x", i.instructionCounter, dst, i.regs[dst], regA, i.regs[regA], regB, i.regs[regB])
	lhs, rhs := uint32(i.regs[regA]), uint32(i.regs[regB])
	if rhs == 0 {
		i.regs[dst] = math.MaxUint64
	} else {
		i.regs[dst] = sext(uint64(lhs/rhs), 4)
	}
	i.skip()
}

// DivSigned32 div_s_32 ω′D =
// ⎧ 2^64 − 1 			if b = 0
// ⎨ a 					if a = −2^31 ∧ b = −1
// ⎩ Z−1_8 (⌊ a ÷ b ⌋) 	otherwise
// where a = Z4(ωA mod 2^32), b = Z4(ωB mod 2^32)
func (i *Instance) DivSigned32(dst polkavm.Reg, regA, regB polkavm.Reg) {
	i.log.Debug().Msgf("%d: div_s_32 %s=0x%x %s=0x%x %s=0x%x", i.instructionCounter, dst, i.regs[dst], regA, i.regs[regA], regB, i.regs[regB])
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

// RemUnsigned32 rem_u_32 ω′D = X4(ωA mod 2^32) if ωB mod 2^32 = 0 otherwise X4((ωA mod 2^32) mod (ωB mod 2^32))
func (i *Instance) RemUnsigned32(dst polkavm.Reg, regA, regB polkavm.Reg) {
	i.log.Debug().Msgf("%d: rem_u_32 %s=0x%x %s=0x%x %s=0x%x", i.instructionCounter, dst, i.regs[dst], regA, i.regs[regA], regB, i.regs[regB])
	lhs, rhs := uint32(i.regs[regA]), uint32(i.regs[regB])
	if rhs == 0 {
		i.regs[dst] = sext(uint64(lhs), 4)
	} else {
		i.regs[dst] = sext(uint64(lhs%rhs), 4)
	}
	i.skip()
}

// RemSigned32 rem_s_32 ω′D =
// ⎧ Z−1_8(a) 			if b = 0
// ⎨ 0			 		if a = −2^31 ∧ b = −1
// ⎩ Z−1_8 (smod(a, b)) otherwise
// where a = Z4(ωA mod 2^32) , b = Z4(ωB mod 2^32)
func (i *Instance) RemSigned32(dst polkavm.Reg, regA, regB polkavm.Reg) {
	i.log.Debug().Msgf("%d: rem_s_32 %s=0x%x %s=0x%x %s=0x%x", i.instructionCounter, dst, i.regs[dst], regA, i.regs[regA], regB, i.regs[regB])
	lhs := int32(uint32(i.regs[regA]))
	rhs := int32(uint32(i.regs[regB]))
	if rhs == 0 {
		i.regs[dst] = uint64(lhs)
	} else if lhs == math.MinInt32 && rhs == -1 {
		i.regs[dst] = uint64(0)
	} else {
		i.regs[dst] = uint64(smod32(lhs, rhs))
	}
	i.skip()
}

// ShiftLogicalLeft32 shlo_l_32 ω′D = X4((ωA ⋅ 2ωB mod 32) mod 2^32)
func (i *Instance) ShiftLogicalLeft32(dst polkavm.Reg, regA, regB polkavm.Reg) {
	i.log.Debug().Msgf("%d: shlo_l_32 %s=0x%x %s=0x%x %s=0x%x", i.instructionCounter, dst, i.regs[dst], regA, i.regs[regA], regB, i.regs[regB])
	i.setAndSkip(dst, sext(uint64(uint32(i.regs[regA])<<(uint32(i.regs[regB])%32)), 4))
}

// ShiftLogicalRight32 shlo_r_32 ω′D = X4(⌊ (ωA mod 2^32) ÷ 2ωB mod 32 ⌋)
func (i *Instance) ShiftLogicalRight32(dst polkavm.Reg, regA, regB polkavm.Reg) {
	i.log.Debug().Msgf("%d: shlo_r_32 %s=0x%x %s=0x%x %s=0x%x", i.instructionCounter, dst, i.regs[dst], regA, i.regs[regA], regB, i.regs[regB])
	i.setAndSkip(dst, sext(uint64(uint32(i.regs[regA])>>(uint32(i.regs[regB])%32)), 4))
}

// ShiftArithmeticRight32 shar_r_32 ω′D = Z−1_8(⌊ Z4(ωA mod 2^32) ÷ 2ωB mod 32 ⌋)
func (i *Instance) ShiftArithmeticRight32(dst polkavm.Reg, regA, regB polkavm.Reg) {
	i.log.Debug().Msgf("%d: shar_r_32 %s=0x%x %s=0x%x %s=0x%x", i.instructionCounter, dst, i.regs[dst], regA, i.regs[regA], regB, i.regs[regB])
	shiftAmount := uint32(i.regs[regB]) % 32
	shiftedValue := int32(uint32(i.regs[regA])) >> shiftAmount
	i.setAndSkip(dst, uint64(shiftedValue))
}

// Add64 add_64 ω′D = (ωA + ωB) mod 2^64
func (i *Instance) Add64(dst polkavm.Reg, regA, regB polkavm.Reg) {
	i.log.Debug().Msgf("%d: add_64 %s=0x%x %s=0x%x %s=0x%x", i.instructionCounter, dst, i.regs[dst], regA, i.regs[regA], regB, i.regs[regB])
	i.setAndSkip(dst, i.regs[regA]+i.regs[regB])
}

// Sub64 sub_64 ω′D = (ωA + 2^64 − ωB) mod 2^64
func (i *Instance) Sub64(dst polkavm.Reg, regA, regB polkavm.Reg) {
	i.log.Debug().Msgf("%d: sub_64 %s=0x%x %s=0x%x %s=0x%x", i.instructionCounter, dst, i.regs[dst], regA, i.regs[regA], regB, i.regs[regB])
	i.setAndSkip(dst, i.regs[regA]-i.regs[regB])
}

// Mul64 mul_64 ω′D = (ωA ⋅ ωB) mod 2^64
func (i *Instance) Mul64(dst polkavm.Reg, regA, regB polkavm.Reg) {
	i.log.Debug().Msgf("%d: mul_64 %s=0x%x %s=0x%x %s=0x%x", i.instructionCounter, dst, i.regs[dst], regA, i.regs[regA], regB, i.regs[regB])
	i.setAndSkip(dst, i.regs[regA]*i.regs[regB])
}

// DivUnsigned64 div_u_64 ω′D = 2^64 − 1 if ωB = 0 otherwise ⌊ ωA ÷ ωB ⌋
func (i *Instance) DivUnsigned64(dst polkavm.Reg, regA, regB polkavm.Reg) {
	i.log.Debug().Msgf("%d: div_u_64 %s=0x%x %s=0x%x %s=0x%x", i.instructionCounter, dst, i.regs[dst], regA, i.regs[regA], regB, i.regs[regB])
	lhs, rhs := i.regs[regA], i.regs[regB]
	if rhs == 0 {
		i.regs[dst] = math.MaxUint64
	} else {
		i.regs[dst] = lhs / rhs
	}
	i.skip()
}

// DivSigned64 div_s_64 ω′D =
// ⎧ 2^64 − 1 						if ωB = 0
// ⎨ ωA								if Z8(ωA) = −2^63 ∧ Z8(ωB) = −1
// ⎩ Z−1_8(⌊ Z8(ωA) ÷ Z8(ωB) ⌋) 	otherwise
func (i *Instance) DivSigned64(dst polkavm.Reg, regA, regB polkavm.Reg) {
	i.log.Debug().Msgf("%d: div_s_64 %s=0x%x %s=0x%x %s=0x%x", i.instructionCounter, dst, i.regs[dst], regA, i.regs[regA], regB, i.regs[regB])
	lhs := int64(i.regs[regA])
	rhs := int64(i.regs[regB])
	if rhs == 0 {
		i.regs[dst] = math.MaxUint64
	} else if lhs == math.MinInt64 && rhs == -1 {
		i.regs[dst] = uint64(lhs)
	} else {
		i.regs[dst] = uint64(lhs / rhs)
	}
	i.skip()
}

// RemUnsigned64 rem_u_64 ω′D = ωA if ωB = 0 otherwise ωA mod ωB
func (i *Instance) RemUnsigned64(dst polkavm.Reg, regA, regB polkavm.Reg) {
	i.log.Debug().Msgf("%d: rem_u_64 %s=0x%x %s=0x%x %s=0x%x", i.instructionCounter, dst, i.regs[dst], regA, i.regs[regA], regB, i.regs[regB])
	lhs, rhs := i.regs[regA], i.regs[regB]
	if rhs == 0 {
		i.regs[dst] = lhs
	} else {
		i.regs[dst] = lhs % rhs
	}
	i.skip()
}

// RemSigned64 rem_s_64 ω′D =
// ⎧ ωA						 	 if ωB = 0
// ⎨ 0 							 if Z8(ωA) = −2^63 ∧ Z8(ωB) = −1
// ⎩ Z−1_8(smod(Z8(ωA), Z8(ωB))) otherwise
func (i *Instance) RemSigned64(dst polkavm.Reg, regA, regB polkavm.Reg) {
	i.log.Debug().Msgf("%d: rem_s_64 %s=0x%x %s=0x%x %s=0x%x", i.instructionCounter, dst, i.regs[dst], regA, i.regs[regA], regB, i.regs[regB])
	lhs, rhs := int64(i.regs[regA]), int64(i.regs[regB])
	if rhs == 0 {
		i.regs[dst] = uint64(lhs)
	} else if lhs == math.MinInt32 && rhs == -1 {
		i.regs[dst] = 0
	} else {
		i.regs[dst] = uint64(smod64(lhs, rhs))
	}
	i.skip()
}

// ShiftLogicalLeft64 shlo_l_64 ω′D = (ωA ⋅ 2ωB mod 64) mod 2^64
func (i *Instance) ShiftLogicalLeft64(dst polkavm.Reg, regA, regB polkavm.Reg) {
	i.log.Debug().Msgf("%d: shlo_l_64 %s=0x%x %s=0x%x %s=0x%x", i.instructionCounter, dst, i.regs[dst], regA, i.regs[regA], regB, i.regs[regB])
	shiftAmount := i.regs[regB] % 64
	shiftedValue := i.regs[regA] << shiftAmount
	i.setAndSkip(dst, shiftedValue)
}

// ShiftLogicalRight64 shlo_r_64 ω′D = ⌊ ωA ÷ 2ωB mod 64 ⌋
func (i *Instance) ShiftLogicalRight64(dst polkavm.Reg, regA, regB polkavm.Reg) {
	i.log.Debug().Msgf("%d: shlo_r_64 %s=0x%x %s=0x%x %s=0x%x", i.instructionCounter, dst, i.regs[dst], regA, i.regs[regA], regB, i.regs[regB])
	i.setAndSkip(dst, i.regs[regA]>>(i.regs[regB]%64))
}

// ShiftArithmeticRight64 shar_r_64 ω′D = Z−1_8(⌊ Z8(ωA) ÷ 2ωB mod 64 ⌋)
func (i *Instance) ShiftArithmeticRight64(dst polkavm.Reg, regA, regB polkavm.Reg) {
	i.log.Debug().Msgf("%d: shar_r_64 %s=0x%x %s=0x%x %s=0x%x", i.instructionCounter, dst, i.regs[dst], regA, i.regs[regA], regB, i.regs[regB])
	shiftAmount := i.regs[regB] % 64
	shiftedValue := int64(i.regs[regA]) >> shiftAmount
	i.setAndSkip(dst, uint64(shiftedValue))
}

// And and ∀i ∈ N64 ∶ B8(ω′D)_i = B8(ωA)_i ∧ B8(ωB)_i
func (i *Instance) And(dst polkavm.Reg, regA, regB polkavm.Reg) {
	i.log.Debug().Msgf("%d: and %s=0x%x %s=0x%x %s=0x%x", i.instructionCounter, dst, i.regs[dst], regA, i.regs[regA], regB, i.regs[regB])
	i.setAndSkip(dst, i.regs[regA]&i.regs[regB])
}

// Xor xor ∀i ∈ N64 ∶ B8(ω′D)_i = B8(ωA)_i ⊕ B8(ωB)_i
func (i *Instance) Xor(dst polkavm.Reg, regA, regB polkavm.Reg) {
	i.log.Debug().Msgf("%d: xor %s=0x%x %s=0x%x %s=0x%x", i.instructionCounter, dst, i.regs[dst], regA, i.regs[regA], regB, i.regs[regB])
	i.setAndSkip(dst, i.regs[regA]^i.regs[regB])
}

// Or or ∀i ∈ N64 ∶ B8(ω′D)_i = B8(ωA)_i ∨ B8(ωB)_i
func (i *Instance) Or(dst polkavm.Reg, regA, regB polkavm.Reg) {
	i.log.Debug().Msgf("%d: or %s=0x%x %s=0x%x %s=0x%x", i.instructionCounter, dst, i.regs[dst], regA, i.regs[regA], regB, i.regs[regB])
	i.setAndSkip(dst, i.regs[regA]|i.regs[regB])
}

// MulUpperSignedSigned mul_upper_s_s ω′D = Z−1_8(⌊ (Z8(ωA) ⋅ Z8(ωB)) ÷ 2^64 ⌋)
func (i *Instance) MulUpperSignedSigned(dst polkavm.Reg, regA, regB polkavm.Reg) {
	i.log.Debug().Msgf("%d: mul_upper_s_s %s=0x%x %s=0x%x %s=0x%x", i.instructionCounter, dst, i.regs[dst], regA, i.regs[regA], regB, i.regs[regB])
	lhs := big.NewInt(int64(i.regs[regA]))
	rhs := big.NewInt(int64(i.regs[regB]))
	mul := lhs.Mul(lhs, rhs)
	i.setAndSkip(dst, uint64(mul.Rsh(mul, 64).Int64()))
}

// MulUpperUnsignedUnsigned mul_upper_u_u ω′D = ⌊ (ωA ⋅ ωB ) ÷ 2^64 ⌋
func (i *Instance) MulUpperUnsignedUnsigned(dst polkavm.Reg, regA, regB polkavm.Reg) {
	i.log.Debug().Msgf("%d: mul_upper_u_u %s=0x%x %s=0x%x %s=0x%x", i.instructionCounter, dst, i.regs[dst], regA, i.regs[regA], regB, i.regs[regB])
	lhs := (&big.Int{}).SetUint64(i.regs[regA])
	rhs := (&big.Int{}).SetUint64(i.regs[regB])
	mul := lhs.Mul(lhs, rhs)
	i.setAndSkip(dst, uint64(mul.Rsh(mul, 64).Int64()))
}

// MulUpperSignedUnsigned mul_upper_s_u ω′D = Z−1_8(⌊ (Z8(ωA) ⋅ ωB) ÷ 2^64 ⌋)
func (i *Instance) MulUpperSignedUnsigned(dst polkavm.Reg, regA, regB polkavm.Reg) {
	i.log.Debug().Msgf("%d: mul_upper_s_u %s=0x%x %s=0x%x %s=0x%x", i.instructionCounter, dst, i.regs[dst], regA, i.regs[regA], regB, i.regs[regB])
	lhs := big.NewInt(int64(i.regs[regA]))
	rhs := (&big.Int{}).SetUint64(i.regs[regB])
	mul := lhs.Mul(lhs, rhs)
	i.setAndSkip(dst, uint64(mul.Rsh(mul, 64).Int64()))
}

// SetLessThanUnsigned set_lt_u ω′D = ωA < ωB
func (i *Instance) SetLessThanUnsigned(dst polkavm.Reg, regA, regB polkavm.Reg) {
	i.log.Debug().Msgf("%d: set_lt_u %s=0x%x %s=0x%x %s=0x%x", i.instructionCounter, dst, i.regs[dst], regA, i.regs[regA], regB, i.regs[regB])
	i.setAndSkip(dst, bool2uint64(i.regs[regA] < i.regs[regB]))
}

// SetLessThanSigned set_lt_s ω′D = Z8(ωA) < Z8(ωB)
func (i *Instance) SetLessThanSigned(dst polkavm.Reg, regA, regB polkavm.Reg) {
	i.log.Debug().Msgf("%d: set_lt_s %s=0x%x %s=0x%x %s=0x%x", i.instructionCounter, dst, i.regs[dst], regA, i.regs[regA], regB, i.regs[regB])
	i.setAndSkip(dst, bool2uint64(int32(i.regs[regA]) < int32(i.regs[regB])))
}

// CmovIfZero cmov_iz ω′D = ωA if ωB = 0 otherwise ωD
func (i *Instance) CmovIfZero(dst polkavm.Reg, s, c polkavm.Reg) {
	i.log.Debug().Msgf("%d: cmov_iz %s=0x%x %s=0x%x %s=0x%x", i.instructionCounter, dst, i.regs[dst], s, i.regs[s], c, i.regs[c])
	if i.regs[c] == 0 {
		i.regs[dst] = i.regs[s]
	}
	i.skip()
}

// CmovIfNotZero cmov_nz ω′D = ωA if ωB ≠ 0 otherwise ωD
func (i *Instance) CmovIfNotZero(dst polkavm.Reg, s, c polkavm.Reg) {
	i.log.Debug().Msgf("%d: cmov_nz %s=0x%x %s=0x%x %s=0x%x", i.instructionCounter, dst, i.regs[dst], s, i.regs[s], c, i.regs[c])
	if i.regs[c] != 0 {
		i.regs[dst] = i.regs[s]
	}
	i.skip()
}

// RotateLeft64 rot_l_64 ∀i ∈ N64 ∶ B8(ω′D)_{(i+ωB) mod 64} = B8(ωA)_i
func (i *Instance) RotateLeft64(dst polkavm.Reg, regA, regB polkavm.Reg) {
	i.log.Debug().Msgf("%d: rot_l_64 %s=0x%x %s=0x%x %s=0x%x", i.instructionCounter, dst, i.regs[dst], regA, i.regs[regA], regB, i.regs[regB])
	i.setAndSkip(dst, bits.RotateLeft64(i.regs[regA], int(i.regs[regB])))
}

// RotateLeft32 rot_l_32 ω′D = X4(x) where x ∈ N2^32, ∀i ∈ N32 ∶ B4(x)_{(i+ωB) mod 32} = B4(ωA)_i
func (i *Instance) RotateLeft32(dst polkavm.Reg, regA, regB polkavm.Reg) {
	i.log.Debug().Msgf("%d: rot_l_32 %s=0x%x %s=0x%x %s=0x%x", i.instructionCounter, dst, i.regs[dst], regA, i.regs[regA], regB, i.regs[regB])
	i.setAndSkip(dst, sext(uint64(bits.RotateLeft32(uint32(i.regs[regA]), int(i.regs[regB]))), 4))
}

// RotateRight64 rot_r_64 ∀i ∈ N64 ∶ B8(ω′D)_i = B8(ωA)_{(i+ωB ) mod 64}
func (i *Instance) RotateRight64(dst polkavm.Reg, regA, regB polkavm.Reg) {
	i.log.Debug().Msgf("%d: rot_r_64 %s=0x%x %s=0x%x %s=0x%x", i.instructionCounter, dst, i.regs[dst], regA, i.regs[regA], regB, i.regs[regB])
	i.setAndSkip(dst, bits.RotateLeft64(i.regs[regA], -int(i.regs[regB])))
}

// RotateRight32 rot_r_32 ω′D = X4(x) where x ∈ N2^32, ∀i ∈ N32 ∶ B4(x)_i = B4(ωA)_{(i+ωB) mod 32}
func (i *Instance) RotateRight32(dst polkavm.Reg, regA, regB polkavm.Reg) {
	i.log.Debug().Msgf("%d: rot_r_32 %s=0x%x %s=0x%x %s=0x%x", i.instructionCounter, dst, i.regs[dst], regA, i.regs[regA], regB, i.regs[regB])
	i.setAndSkip(dst, sext(uint64(bits.RotateLeft32(uint32(i.regs[regA]), -int(i.regs[regB]))), 4))
}

// AndInverted and_inv ∀i ∈ N64 ∶ B8(ω′D)_i = B8(ωA)i ∧ ¬B8(ωB)_i
func (i *Instance) AndInverted(dst polkavm.Reg, regA, regB polkavm.Reg) {
	i.log.Debug().Msgf("%d: and_inv %s=0x%x %s=0x%x %s=0x%x", i.instructionCounter, dst, i.regs[dst], regA, i.regs[regA], regB, i.regs[regB])
	i.setAndSkip(dst, i.regs[regA]&^i.regs[regB])
}

// OrInverted or_inv ∀i ∈ N64 ∶ B8(ω′D)_i = B8(ωA)i ∨ ¬B8(ωB)_i
func (i *Instance) OrInverted(dst polkavm.Reg, regA, regB polkavm.Reg) {
	i.log.Debug().Msgf("%d: or_inv %s=0x%x %s=0x%x %s=0x%x", i.instructionCounter, dst, i.regs[dst], regA, i.regs[regA], regB, i.regs[regB])
	i.setAndSkip(dst, i.regs[regA]|^i.regs[regB])
}

// Xnor xnor ∀i ∈ N64 ∶ B8(ω′D)_i = ¬(B8(ωA)_i ⊕ B8(ωB)_i)
func (i *Instance) Xnor(dst polkavm.Reg, regA, regB polkavm.Reg) {
	i.log.Debug().Msgf("%d: xnor %s=0x%x %s=0x%x %s=0x%x", i.instructionCounter, dst, i.regs[dst], regA, i.regs[regA], regB, i.regs[regB])
	i.setAndSkip(dst, ^(i.regs[regA] ^ i.regs[regB]))
}

// Max max ω′D = max(Z8(ωA), Z8(ωB))
func (i *Instance) Max(dst polkavm.Reg, regA, regB polkavm.Reg) {
	i.log.Debug().Msgf("%d: max %s=0x%x %s=0x%x %s=0x%x", i.instructionCounter, dst, i.regs[dst], regA, i.regs[regA], regB, i.regs[regB])
	i.setAndSkip(dst, uint64(max(int64(i.regs[regA]), int64(i.regs[regB]))))
}

// MaxUnsigned max_u ω′D = max(ωA, ωB)
func (i *Instance) MaxUnsigned(dst polkavm.Reg, regA, regB polkavm.Reg) {
	i.log.Debug().Msgf("%d: max_u %s=0x%x %s=0x%x %s=0x%x", i.instructionCounter, dst, i.regs[dst], regA, i.regs[regA], regB, i.regs[regB])
	i.setAndSkip(dst, max(i.regs[regA], i.regs[regB]))
}

// Min min ω′D = min(Z8(ωA), Z8(ωB))
func (i *Instance) Min(dst polkavm.Reg, regA, regB polkavm.Reg) {
	i.log.Debug().Msgf("%d: min %s=0x%x %s=0x%x %s=0x%x", i.instructionCounter, dst, i.regs[dst], regA, i.regs[regA], regB, i.regs[regB])
	i.setAndSkip(dst, uint64(min(int64(i.regs[regA]), int64(i.regs[regB]))))
}

// MinUnsigned min_u ω′D = min(ωA, ωB)
func (i *Instance) MinUnsigned(dst polkavm.Reg, regA, regB polkavm.Reg) {
	i.log.Debug().Msgf("%d: min_u %s=0x%x %s=0x%x %s=0x%x", i.instructionCounter, dst, i.regs[dst], regA, i.regs[regA], regB, i.regs[regB])
	i.setAndSkip(dst, min(i.regs[regA], i.regs[regB]))
}

func bool2uint64(v bool) uint64 {
	if v {
		return 1
	}
	return 0
}

// smod (a Z, b Z) → Z a if b = 0 otherwise sgn(a)(|a| mod |b|) (eq. A.32)
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

// smod (a Z, b Z) → Z a if b = 0 otherwise sgn(a)(|a| mod |b|) (eq. A.32)
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
