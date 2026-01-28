package pvm

import (
	"encoding/binary"
	"math"
	"math/big"
	"math/bits"
)

// Trap trap ε = ☇
func (i *Instance) Trap() error {
	return ErrPanicf("explicit trap")
}

// Fallthrough fallthrough
func (i *Instance) Fallthrough() {
	i.skip()
}

// Unlikely unlikely
func (i *Instance) Unlikely() {
	i.skip()
}

// LoadImm64 load_imm_64 φ′A = νX
func (i *Instance) LoadImm64(dst Reg, imm uint64) {
	i.setAndSkip(dst, imm)
}

// StoreImmU8 store_imm_u8 μ′↺νX = νY mod 28
func (i *Instance) StoreImmU8(address uint64, value uint64) error {
	i.storeBuf[0] = uint8(value)
	if err := i.memory.Write(uint32(address), i.storeBuf[:1]); err != nil {
		return err
	}
	i.skip()
	return nil
}

// StoreImmU16 store_imm_u16 μ′↺{νX...+2} = E2(νY mod 2^16)
func (i *Instance) StoreImmU16(address uint64, value uint64) error {
	binary.LittleEndian.PutUint16(i.storeBuf[:2], uint16(value))
	if err := i.memory.Write(uint32(address), i.storeBuf[:2]); err != nil {
		return err
	}
	i.skip()
	return nil
}

// StoreImmU32 store_imm_u32 μ′↺{νX...+4} = E4(νY mod 2^32)
func (i *Instance) StoreImmU32(address uint64, value uint64) error {
	binary.LittleEndian.PutUint32(i.storeBuf[:4], uint32(value))
	if err := i.memory.Write(uint32(address), i.storeBuf[:4]); err != nil {
		return err
	}
	i.skip()
	return nil
}

// StoreImmU64 store_imm_u64 μ′↺{νX...+8} = E8(νY)
func (i *Instance) StoreImmU64(address uint64, value uint64) error {
	binary.LittleEndian.PutUint64(i.storeBuf[:8], value)
	if err := i.memory.Write(uint32(address), i.storeBuf[:8]); err != nil {
		return err
	}
	i.skip()
	return nil
}

// Jump jump branch(νX , ⊺)
func (i *Instance) Jump(target uint64) error {
	return i.branch(true, target)
}

// JumpInd jump_ind djump((φA + νX) mod 2^32)
func (i *Instance) JumpInd(base Reg, offset uint64) error {
	return i.djump(uint32(i.regs[base] + offset))
}

// LoadImm load_imm φ′A = νX
func (i *Instance) LoadImm(dst Reg, imm uint64) {
	i.setAndSkip(dst, imm)
}

// LoadU8 load_u8 φ′A = μ↺_νX
func (i *Instance) LoadU8(dst Reg, address uint64) error {
	slice := i.loadBuf[:1]
	if err := i.memory.Read(uint32(address), slice); err != nil {
		return err
	}
	i.setAndSkip(dst, uint64(slice[0]))
	return nil
}

// LoadI8 load_i8 φ′A = X1(μ↺_νX)
func (i *Instance) LoadI8(dst Reg, address uint64) error {
	slice := i.loadBuf[:1]
	if err := i.memory.Read(uint32(address), slice); err != nil {
		return err
	}
	i.setAndSkip(dst, uint64(int8(slice[0])))
	return nil
}

// LoadU16 load_u16 φ′A = E−1_2 (μ↺_{νX...+2})
func (i *Instance) LoadU16(dst Reg, address uint64) error {
	slice := i.loadBuf[:2]
	if err := i.memory.Read(uint32(address), slice); err != nil {
		return err
	}
	i.setAndSkip(dst, uint64(binary.LittleEndian.Uint16(slice)))
	return nil
}

// LoadI16 load_i16 φ′A = X2(E−1_2 (μ↺_{νX...+2})
func (i *Instance) LoadI16(dst Reg, address uint64) error {
	slice := i.loadBuf[:2]
	if err := i.memory.Read(uint32(address), slice); err != nil {
		return err
	}
	i.setAndSkip(dst, uint64(int16(binary.LittleEndian.Uint16(slice))))
	return nil
}

// LoadU32 load_u32 φ′A = E−1_4 (μ↺_{νX...+4})
func (i *Instance) LoadU32(dst Reg, address uint64) error {
	slice := i.loadBuf[:4]
	if err := i.memory.Read(uint32(address), slice); err != nil {
		return err
	}
	i.setAndSkip(dst, uint64(binary.LittleEndian.Uint32(slice)))
	return nil
}

// LoadI32 load_i32 φ′A = X4(E−1_4(μ↺_{νX...+4}))
func (i *Instance) LoadI32(dst Reg, address uint64) error {
	slice := i.loadBuf[:4]
	if err := i.memory.Read(uint32(address), slice); err != nil {
		return err
	}
	i.setAndSkip(dst, sext(uint64(binary.LittleEndian.Uint32(slice)), 4))
	return nil
}

// LoadU64 load_u64 φ′A = E−1_8 (μ↺_{νX...+8})
func (i *Instance) LoadU64(dst Reg, address uint64) error {
	slice := i.loadBuf[:8]
	if err := i.memory.Read(uint32(address), slice); err != nil {
		return err
	}
	i.setAndSkip(dst, binary.LittleEndian.Uint64(slice))
	return nil
}

// StoreU8 store_u8 μ′↺_νX = φA mod 2^8
func (i *Instance) StoreU8(src Reg, address uint64) error {
	i.storeBuf[0] = uint8(i.regs[src])
	if err := i.memory.Write(uint32(address), i.storeBuf[:1]); err != nil {
		return err
	}
	i.skip()
	return nil
}

// StoreU16 store_u16 μ′↺_{νX...+2} = E2(φA mod 2^16)
func (i *Instance) StoreU16(src Reg, address uint64) error {
	binary.LittleEndian.PutUint16(i.storeBuf[:2], uint16(i.regs[src]))
	if err := i.memory.Write(uint32(address), i.storeBuf[:2]); err != nil {
		return err
	}
	i.skip()
	return nil
}

// StoreU32 store_u32 μ′↺_{νX...+4} = E4(φA mod 2^32)
func (i *Instance) StoreU32(src Reg, address uint64) error {
	binary.LittleEndian.PutUint32(i.storeBuf[:4], uint32(i.regs[src]))
	if err := i.memory.Write(uint32(address), i.storeBuf[:4]); err != nil {
		return err
	}
	i.skip()
	return nil
}

// StoreU64 store_u64 μ′↺_{νX...+8} = E8(φA)
func (i *Instance) StoreU64(src Reg, address uint64) error {
	binary.LittleEndian.PutUint64(i.storeBuf[:8], i.regs[src])
	if err := i.memory.Write(uint32(address), i.storeBuf[:8]); err != nil {
		return err
	}
	i.skip()
	return nil
}

// StoreImmIndU8 store_imm_ind_u8 μ′↺_{φA+νX} = νY mod 2^8
func (i *Instance) StoreImmIndU8(base Reg, offset uint64, value uint64) error {
	i.storeBuf[0] = uint8(value)
	if err := i.memory.Write(uint32(i.regs[base]+offset), i.storeBuf[:1]); err != nil {
		return err
	}
	i.skip()
	return nil
}

// StoreImmIndU16 store_imm_ind_u16 μ′↺_{φA+νX...+2} = E2(νY mod 2^16)
func (i *Instance) StoreImmIndU16(base Reg, offset uint64, value uint64) error {
	binary.LittleEndian.PutUint16(i.storeBuf[:2], uint16(value))
	if err := i.memory.Write(uint32(i.regs[base]+offset), i.storeBuf[:2]); err != nil {
		return err
	}
	i.skip()
	return nil
}

// StoreImmIndU32 store_imm_ind_u32 μ′↺_{φA+νX...+4} = E4(νY mod 2^32)
func (i *Instance) StoreImmIndU32(base Reg, offset uint64, value uint64) error {
	binary.LittleEndian.PutUint32(i.storeBuf[:4], uint32(value))
	if err := i.memory.Write(uint32(i.regs[base]+offset), i.storeBuf[:4]); err != nil {
		return err
	}
	i.skip()
	return nil
}

// StoreImmIndU64 store_imm_ind_u64 μ′↺_{φA+νX...+8} = E8(νY)
func (i *Instance) StoreImmIndU64(base Reg, offset uint64, value uint64) error {
	binary.LittleEndian.PutUint64(i.storeBuf[:8], value)
	if err := i.memory.Write(uint32(i.regs[base]+offset), i.storeBuf[:8]); err != nil {
		return err
	}
	i.skip()
	return nil
}

// LoadImmJump load_imm_jump branch(νY , ⊺), φ′A = νX
func (i *Instance) LoadImmJump(ra Reg, value uint64, target uint64) error {
	i.regs[ra] = value
	return i.branch(true, target)
}

// BranchEqImm branch_eq_imm branch(νY, φA = νX)
func (i *Instance) BranchEqImm(regA Reg, valueX uint64, target uint64) error {
	return i.branch(i.regs[regA] == valueX, target)
}

// BranchNeImm branch_ne_imm branch(νY, φA ≠ νX)
func (i *Instance) BranchNeImm(regA Reg, valueX uint64, target uint64) error {
	return i.branch(i.regs[regA] != valueX, target)
}

// BranchLtUImm branch_lt_u_imm branch(νY , φA < νX)
func (i *Instance) BranchLtUImm(regA Reg, valueX uint64, target uint64) error {
	return i.branch(i.regs[regA] < valueX, target)
}

// BranchLeUImm branch_le_u_imm branch(νY, φA ≤ νX)
func (i *Instance) BranchLeUImm(regA Reg, valueX uint64, target uint64) error {
	return i.branch(i.regs[regA] <= valueX, target)
}

// BranchGeUImm branch_ge_u_imm branch(νY, φA ≥ νX)
func (i *Instance) BranchGeUImm(regA Reg, valueX uint64, target uint64) error {
	return i.branch(i.regs[regA] >= valueX, target)
}

// BranchGtUImm branch_gt_u_imm branch(νY, φA > νX)
func (i *Instance) BranchGtUImm(regA Reg, valueX uint64, target uint64) error {
	return i.branch(i.regs[regA] > valueX, target)
}

// BranchLtSImm branch_lt_s_imm branch(νY, Z8(φA) < Z8(νX))
func (i *Instance) BranchLtSImm(regA Reg, valueX uint64, target uint64) error {
	return i.branch(int64(i.regs[regA]) < int64(valueX), target)
}

// BranchLeSImm branch_le_s_imm branch(νY , Z8(φA) ≤ Z8(νX))
func (i *Instance) BranchLeSImm(regA Reg, valueX uint64, target uint64) error {
	return i.branch(int64(i.regs[regA]) <= int64(valueX), target)
}

// BranchGeSImm branch_ge_s_imm branch(νY, Z8(φA) ≥ Z8(νX))
func (i *Instance) BranchGeSImm(regA Reg, valueX uint64, target uint64) error {
	return i.branch(int64(i.regs[regA]) >= int64(valueX), target)
}

// BranchGtSImm branch_gt_s_imm branch(νY, Z8(φA) > Z8(νX))
func (i *Instance) BranchGtSImm(regA Reg, valueX uint64, target uint64) error {
	return i.branch(int64(i.regs[regA]) > int64(valueX), target)
}

// MoveReg move_reg φ′D = φA
func (i *Instance) MoveReg(dst Reg, s Reg) {
	i.setAndSkip(dst, i.regs[s])
}

// CountSetBits64 count_set_bits_64 φ′D = {63;i=0}∑ B8(φA)_i
func (i *Instance) CountSetBits64(dst Reg, s Reg) {
	i.setAndSkip(dst, uint64(bits.OnesCount64(i.regs[s])))
}

// CountSetBits32 count_set_bits_32 φ′D = {31;i=0}∑ B4(φA mod 2^32)_i
func (i *Instance) CountSetBits32(dst Reg, s Reg) {
	i.setAndSkip(dst, uint64(bits.OnesCount32(uint32(i.regs[s]))))
}

// LeadingZeroBits64 leading_zero_bits_64 φ′D = max(n ∈ N65) where {i<n;i=0}∑ ←B8(φA)_i = 0
func (i *Instance) LeadingZeroBits64(dst Reg, s Reg) {
	i.setAndSkip(dst, uint64(bits.LeadingZeros64(i.regs[s])))
}

// LeadingZeroBits32 leading_zero_bits_32 φ′D = max(n ∈ N33) where {i<n;i=0}∑ ←B4(φA mod 232)_i = 0
func (i *Instance) LeadingZeroBits32(dst Reg, s Reg) {
	i.setAndSkip(dst, uint64(bits.LeadingZeros32(uint32(i.regs[s]))))
}

// TrailingZeroBits64 trailing_zero_bits_64 φ′D = max(n ∈ N65) where {i<n;i=0}∑ B8(φA)_i = 0
func (i *Instance) TrailingZeroBits64(dst Reg, s Reg) {
	i.setAndSkip(dst, uint64(bits.TrailingZeros64(i.regs[s])))
}

// TrailingZeroBits32 trailing_zero_bits_32 φ′D = max(n ∈ N33) where {i<n;i=0}∑ B4(φA mod 232)_i = 0
func (i *Instance) TrailingZeroBits32(dst Reg, s Reg) {
	i.setAndSkip(dst, uint64(bits.TrailingZeros32(uint32(i.regs[s]))))
}

// SignExtend8 sign_extend_8 φ′D = Z−1_8(Z_1(φA mod 2^8))
func (i *Instance) SignExtend8(dst Reg, s Reg) {
	i.setAndSkip(dst, uint64(int8(uint8(i.regs[s]))))
}

// SignExtend16 sign_extend_16 φ′D = Z−1_8(Z_2(φA mod 2^16))
func (i *Instance) SignExtend16(dst Reg, s Reg) {
	i.setAndSkip(dst, uint64(int16(uint16(i.regs[s]))))
}

// ZeroExtend16 zero_extend_16 φ′D = φA mod 2^16
func (i *Instance) ZeroExtend16(dst Reg, s Reg) {
	i.setAndSkip(dst, uint64(uint16(i.regs[s])))
}

// ReverseBytes reverse_bytes ∀i ∈ N8 ∶ E8(φ′D)i = E8(φA)_7−i
func (i *Instance) ReverseBytes(dst Reg, s Reg) {
	i.setAndSkip(dst, bits.ReverseBytes64(i.regs[s]))
}

// StoreIndU8 store_ind_u8 μ′↺_{φB+νX} = φA mod 2^8
func (i *Instance) StoreIndU8(src Reg, base Reg, offset uint64) error {
	i.storeBuf[0] = uint8(i.regs[src])
	if err := i.memory.Write(uint32(i.regs[base]+offset), i.storeBuf[:1]); err != nil {
		return err
	}
	i.skip()
	return nil
}

// StoreIndU16 store_ind_u16 μ′↺_{φB+νX...+2} = E2(φA mod 2^16)
func (i *Instance) StoreIndU16(src Reg, base Reg, offset uint64) error {
	binary.LittleEndian.PutUint16(i.storeBuf[:2], uint16(i.regs[src]))
	if err := i.memory.Write(uint32(i.regs[base]+offset), i.storeBuf[:2]); err != nil {
		return err
	}
	i.skip()
	return nil
}

// StoreIndU32 store_ind_u32 μ′↺_{φB+νX...+4} = E4(φA mod 2^32)
func (i *Instance) StoreIndU32(src Reg, base Reg, offset uint64) error {
	binary.LittleEndian.PutUint32(i.storeBuf[:4], uint32(i.regs[src]))
	if err := i.memory.Write(uint32(i.regs[base]+offset), i.storeBuf[:4]); err != nil {
		return err
	}
	i.skip()
	return nil
}

// StoreIndU64 store_ind_u64 μ′↺_{φB+νX...+8} = E8(φA)
func (i *Instance) StoreIndU64(src Reg, base Reg, offset uint64) error {
	binary.LittleEndian.PutUint64(i.storeBuf[:8], i.regs[src])
	if err := i.memory.Write(uint32(i.regs[base]+offset), i.storeBuf[:8]); err != nil {
		return err
	}
	i.skip()
	return nil
}

// LoadIndU8 load_ind_u8 φ′A = μ↺_{φB+νX}
func (i *Instance) LoadIndU8(dst Reg, base Reg, offset uint64) error {
	slice := i.loadBuf[:1]
	if err := i.memory.Read(uint32(i.regs[base]+offset), slice); err != nil {
		return err
	}
	i.setAndSkip(dst, uint64(slice[0]))
	return nil
}

// LoadIndI8 load_ind_i8 φ′A = Z−1_8(Z1(μ↺_{φB+νX}))
func (i *Instance) LoadIndI8(dst Reg, base Reg, offset uint64) error {
	slice := i.loadBuf[:1]
	if err := i.memory.Read(uint32(i.regs[base]+offset), slice); err != nil {
		return err
	}
	i.setAndSkip(dst, uint64(int8(slice[0])))
	return nil
}

// LoadIndU16 load_ind_u16 φ′A = E−1_2 (μ↺_{φB+νX...+2})
func (i *Instance) LoadIndU16(dst Reg, base Reg, offset uint64) error {
	slice := i.loadBuf[:2]
	if err := i.memory.Read(uint32(i.regs[base]+offset), slice); err != nil {
		return err
	}
	i.setAndSkip(dst, uint64(binary.LittleEndian.Uint16(slice)))
	return nil
}

// LoadIndI16 load_ind_i16 φ′A = Z−1_8(Z2(E−1_2(μ↺_{φB+νX...+2})))
func (i *Instance) LoadIndI16(dst Reg, base Reg, offset uint64) error {
	slice := i.loadBuf[:2]
	if err := i.memory.Read(uint32(i.regs[base]+offset), slice); err != nil {
		return err
	}
	i.setAndSkip(dst, uint64(int16(binary.LittleEndian.Uint16(slice))))
	return nil
}

// LoadIndU32 load_ind_u32 φ′A = E−1_4(μ↺_{φB+νX...+4})
func (i *Instance) LoadIndU32(dst Reg, base Reg, offset uint64) error {
	slice := i.loadBuf[:4]
	if err := i.memory.Read(uint32(i.regs[base]+offset), slice); err != nil {
		return err
	}
	i.setAndSkip(dst, uint64(binary.LittleEndian.Uint32(slice)))
	return nil
}

// LoadIndI32 load_ind_i32 φ′A = Z−1_8(Z4(E−1_4(μ↺_{φB+νX...+4})))
func (i *Instance) LoadIndI32(dst Reg, base Reg, offset uint64) error {
	slice := i.loadBuf[:4]
	if err := i.memory.Read(uint32(i.regs[base]+offset), slice); err != nil {
		return err
	}
	i.setAndSkip(dst, uint64(int32(binary.LittleEndian.Uint32(slice))))
	return nil
}

// LoadIndU64 load_ind_u64 φ′A = E−1_8(μ↺_{φB+νX...+8})
func (i *Instance) LoadIndU64(dst Reg, base Reg, offset uint64) error {
	slice := i.loadBuf[:8]
	if err := i.memory.Read(uint32(i.regs[base]+offset), slice); err != nil {
		return err
	}
	i.setAndSkip(dst, binary.LittleEndian.Uint64(slice))
	return nil
}

// AddImm32 add_imm_32 φ′A = X4((φB + νX) mod 2^32)
func (i *Instance) AddImm32(dst Reg, regA Reg, value uint64) {
	i.setAndSkip(dst, sext(uint64(uint32(i.regs[regA]+value)), 4))
}

// AndImm and_imm ∀i ∈ N64 ∶ B8(φ′A)_i = B8(φB)_i ∧ B8(νX)_i
func (i *Instance) AndImm(dst Reg, regA Reg, value uint64) {
	i.setAndSkip(dst, (i.regs[regA])&value)
}

// XorImm xor_imm ∀i ∈ N64 ∶ B8(φ′A)i = B8(φB)_i ⊕ B8(νX)_i
func (i *Instance) XorImm(dst Reg, regA Reg, value uint64) {
	i.setAndSkip(dst, (i.regs[regA])^value)
}

// OrImm or_imm ∀i ∈ N64 ∶ B8(φ′A)i = B8(φB)_i ∨ B8(νX)_i
func (i *Instance) OrImm(dst Reg, regA Reg, value uint64) {
	i.setAndSkip(dst, (i.regs[regA])|value)
}

// MulImm32 mul_imm_32 φ′A = X4((φB ⋅ νX) mod 2^32)
func (i *Instance) MulImm32(dst Reg, regA Reg, value uint64) {
	i.setAndSkip(dst, sext(uint64(uint32(i.regs[regA]*value)), 4))
}

// SetLtUImm set_lt_u_imm φ′A = φB < νX
func (i *Instance) SetLtUImm(dst Reg, regA Reg, value uint64) {
	i.setAndSkip(dst, bool2uint64((i.regs[regA]) < value))
}

// SetLtSImm set_lt_s_imm φ′A = Z8(φB) < Z8(νX)
func (i *Instance) SetLtSImm(dst Reg, regA Reg, value uint64) {
	i.setAndSkip(dst, bool2uint64(int64(i.regs[regA]) < int64(value)))
}

// ShloLImm32 shlo_l_imm_32 φ′A = X4((φB ⋅ 2^νX mod 32) mod 2^32)
func (i *Instance) ShloLImm32(dst Reg, regA Reg, value uint64) {
	i.setAndSkip(dst, sext(uint64(uint32(i.regs[regA])<<value), 4))
}

// ShloRImm32 shlo_r_imm_32 φ′A = X4(⌊ φB mod 2^32 ÷ 2^νX mod 32 ⌋)
func (i *Instance) ShloRImm32(dst Reg, regA Reg, value uint64) {
	i.setAndSkip(dst, sext(uint64(uint32(i.regs[regA])>>value), 4))
}

// SharRImm32 shar_r_imm_32 φ′A = Z−1_8(⌊ Z4(φB mod 2^32) ÷ 2^νX mod 32 ⌋)
func (i *Instance) SharRImm32(dst Reg, regA Reg, value uint64) {
	i.setAndSkip(dst, uint64(int32(uint32(i.regs[regA]))>>value))
}

// NegAddImm32 neg_add_imm_32 φ′A = X4((νX + 2^32 − φB) mod 2^32)
func (i *Instance) NegAddImm32(dst Reg, regA Reg, value uint64) {
	i.setAndSkip(dst, sext(uint64(uint32(value-i.regs[regA])), 4))
}

// SetGtUImm set_gt_u_imm φ′A = φB > νX
func (i *Instance) SetGtUImm(dst Reg, regA Reg, value uint64) {
	i.setAndSkip(dst, bool2uint64(i.regs[regA] > value))
}

// SetGtSImm set_gt_s_imm φ′A = Z8(φB) > Z8(νX)
func (i *Instance) SetGtSImm(dst Reg, regA Reg, value uint64) {
	i.setAndSkip(dst, bool2uint64(int64(i.regs[regA]) > int64(value)))
}

// ShloLImmAlt32 shlo_l_imm_alt_32 φ′A = X4((νX ⋅ 2φB mod 32) mod 2^32)
func (i *Instance) ShloLImmAlt32(dst Reg, regB Reg, value uint64) {
	i.setAndSkip(dst, sext(uint64(uint32(value<<(i.regs[regB]&31))), 4))
}

// SharRImmAlt32 shlo_r_imm_alt_32 φ′A = X4(⌊ νX mod 2^32 ÷ 2^φB mod 32 ⌋)
func (i *Instance) SharRImmAlt32(dst Reg, regB Reg, value uint64) {
	i.setAndSkip(dst, sext(uint64(uint32(value)>>uint32(i.regs[regB]&31)), 4))
}

// ShloRImmAlt32 shar_r_imm_alt_32 φ′A = Z−1_8(⌊ Z4(νX mod 2^32) ÷ 2φB mod 32 ⌋)
func (i *Instance) ShloRImmAlt32(dst Reg, regB Reg, value uint64) {
	i.setAndSkip(dst, uint64(int32(uint32(value))>>uint32(i.regs[regB]&31)))
}

// CmovIzImm cmov_iz_imm φ′A = νX if φB = 0 otherwise φA
func (i *Instance) CmovIzImm(dst Reg, c Reg, s uint64) {
	if i.regs[c] == 0 {
		i.regs[dst] = s
	}
	i.skip()
}

// CmovNzImm cmov_nz_imm φ′A = νX if φB ≠ 0 otherwise φA
func (i *Instance) CmovNzImm(dst Reg, c Reg, s uint64) {
	if i.regs[c] != 0 {
		i.regs[dst] = s
	}

	i.skip()
}

// AddImm64 add_imm_64 φ′A = (φB + νX) mod 2^64
func (i *Instance) AddImm64(dst Reg, regA Reg, value uint64) {
	i.setAndSkip(dst, i.regs[regA]+value)
}

// MulImm64 mul_imm_64 φ′A = (φB ⋅ νX) mod 2^64
func (i *Instance) MulImm64(dst Reg, regA Reg, value uint64) {
	i.setAndSkip(dst, i.regs[regA]*value)
}

// ShloLImm64 shlo_l_imm_64 φ′A = X8((φB ⋅ 2^νX mod 64) mod 2^64)
func (i *Instance) ShloLImm64(dst Reg, regA Reg, value uint64) {
	i.setAndSkip(dst, sext(i.regs[regA]<<value, 8))
}

// ShloRImm64 shlo_r_imm_64 φ′A = X8(⌊ φB ÷ 2^νX mod 64 ⌋)
func (i *Instance) ShloRImm64(dst Reg, regA Reg, value uint64) {
	i.setAndSkip(dst, sext(i.regs[regA]>>value, 8))
}

// SharRImm64 shar_r_imm_64 φ′A = Z−1_8(⌊ Z8(φB) ÷ 2νX mod 64 ⌋)
func (i *Instance) SharRImm64(dst Reg, regA Reg, value uint64) {
	i.setAndSkip(dst, uint64(int64(i.regs[regA])>>value))
}

// NegAddImm64 neg_add_imm_64 φ′A = (νX + 2^64 − φB) mod 2^64
func (i *Instance) NegAddImm64(dst Reg, regA Reg, value uint64) {
	i.setAndSkip(dst, value-i.regs[regA])
}

// ShloLImmAlt64 shlo_l_imm_alt_64 φ′A = (νX ⋅ 2φB mod 64) mod 2^64
func (i *Instance) ShloLImmAlt64(dst Reg, regB Reg, value uint64) {
	i.setAndSkip(dst, value<<(i.regs[regB]&63))
}

// ShloRImmAlt64 shlo_r_imm_alt_64 φ′A = ⌊ νX ÷ 2^φB mod 64 ⌋
func (i *Instance) ShloRImmAlt64(dst Reg, regB Reg, value uint64) {
	i.setAndSkip(dst, value>>(i.regs[regB]&63))
}

// SharRImmAlt64 shar_r_imm_alt_64 φ′A = Z−1_8(⌊ Z8(νX) ÷ 2φB mod 64 ⌋)
func (i *Instance) SharRImmAlt64(dst Reg, regB Reg, value uint64) {
	i.setAndSkip(dst, uint64(int64(value)>>(i.regs[regB]&63)))
}

// RotateRight64Imm rot_r_64_imm ∀i ∈ N64 ∶ B8(φ′A)_i = B8(φB)_{(i+νX) mod 64}
func (i *Instance) RotateRight64Imm(dst Reg, regA Reg, value uint64) {
	i.setAndSkip(dst, bits.RotateLeft64(i.regs[regA], -int(value)))
}

// RotateRight64ImmAlt rot_r_64_imm_alt ∀i ∈ N64 ∶ B8(φ′A)i = B8(νX)_{(i+φB) mod 64}
func (i *Instance) RotateRight64ImmAlt(dst Reg, regA Reg, value uint64) {
	i.setAndSkip(dst, bits.RotateLeft64(value, -int(i.regs[regA])))
}

// RotateRight32Imm rot_r_32_imm φ′A = X4(x) where x ∈ N2^32, ∀i ∈ N32 ∶ B4(x)_i = B4(φB)_{(i+νX ) mod 32}
func (i *Instance) RotateRight32Imm(dst Reg, regA Reg, value uint64) {
	i.setAndSkip(dst, sext(uint64(bits.RotateLeft32(uint32(i.regs[regA]), -int(value))), 4))
}

// RotateRight32ImmAlt rot_r_32_imm_alt φ′A = X4(x) where x ∈ N2^32, ∀i ∈ N32 ∶ B4(x)_i = B4(νX)_{(i+φB) mod 32}
func (i *Instance) RotateRight32ImmAlt(dst Reg, regA Reg, value uint64) {
	i.setAndSkip(dst, sext(uint64(bits.RotateLeft32(uint32(value), -int(uint32(i.regs[regA])))), 4))
}

// BranchEq branch_eq branch(νX, φA = φB)
func (i *Instance) BranchEq(regA Reg, regB Reg, target uint64) error {
	return i.branch(i.regs[regA] == i.regs[regB], target)
}

// BranchNe branch_ne branch(νX, φA ≠ φB)
func (i *Instance) BranchNe(regA Reg, regB Reg, target uint64) error {
	return i.branch(i.regs[regA] != i.regs[regB], target)
}

// BranchLtU branch_lt_u branch(νX, φA < φB)
func (i *Instance) BranchLtU(regA Reg, regB Reg, target uint64) error {
	return i.branch(i.regs[regA] < i.regs[regB], target)
}

// BranchLtS branch_lt_s branch(νX, Z8(φA) < Z8(φB))
func (i *Instance) BranchLtS(regA Reg, regB Reg, target uint64) error {
	return i.branch(int64(i.regs[regA]) < int64(i.regs[regB]), target)
}

// BranchGeU branch_ge_u branch(νX, φA ≥ φB)
func (i *Instance) BranchGeU(regA Reg, regB Reg, target uint64) error {
	return i.branch(i.regs[regA] >= i.regs[regB], target)
}

// BranchGeS branch_ge_s branch(νX, Z8(φA) ≥ Z8(φB))
func (i *Instance) BranchGeS(regA Reg, regB Reg, target uint64) error {
	return i.branch(int64(i.regs[regA]) >= int64(i.regs[regB]), target)
}

// LoadImmJumpInd load_imm_jump_ind djump((φB + νY) mod 232), φ′A = νX
func (i *Instance) LoadImmJumpInd(regA Reg, base Reg, value, offset uint64) error {
	target := i.regs[base] + offset
	i.regs[regA] = value
	return i.djump(uint32(target))
}

// Add32 add_32 φ′D = X4((φA + φB) mod 2^32)
func (i *Instance) Add32(dst Reg, regA, regB Reg) {
	i.setAndSkip(dst, sext(uint64(uint32(i.regs[regA]+i.regs[regB])), 4))
}

// Sub32 sub_32 φ′D = X4((φA + 2^32 − (φB mod 2^32)) mod 2^32)
func (i *Instance) Sub32(dst Reg, regA, regB Reg) {
	i.setAndSkip(dst, sext(uint64(uint32(i.regs[regA]-i.regs[regB])), 4))
}

// Mul32 mul_32 φ′D = X4((φA ⋅ φB) mod 2^32)
func (i *Instance) Mul32(dst Reg, regA, regB Reg) {
	i.setAndSkip(dst, sext(uint64(uint32(i.regs[regA]*i.regs[regB])), 4))
}

// DivU32 div_u_32 φ′D = 2^64 − 1 if φB mod 2^32 = 0 otherwise X4(⌊ (φA mod 2^32) ÷ (φB mod 2^32) ⌋)
func (i *Instance) DivU32(dst Reg, regA, regB Reg) {
	lhs, rhs := uint32(i.regs[regA]), uint32(i.regs[regB])
	if rhs == 0 {
		i.regs[dst] = math.MaxUint64
	} else {
		i.regs[dst] = sext(uint64(lhs/rhs), 4)
	}
	i.skip()
}

// DivS32 div_s_32 φ′D =
// ⎧ 2^64 − 1 			if b = 0
// ⎨ Z−1_8(a) 			if a = −2^31 ∧ b = −1
// ⎩ Z−1_8 (rtz(a ÷ b)) otherwise
// where a = Z4(φA mod 2^32), b = Z4(φB mod 2^32)
func (i *Instance) DivS32(dst Reg, regA, regB Reg) {
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

// RemU32 rem_u_32 φ′D = X4(φA mod 2^32) if φB mod 2^32 = 0 otherwise X4((φA mod 2^32) mod (φB mod 2^32))
func (i *Instance) RemU32(dst Reg, regA, regB Reg) {
	lhs, rhs := uint32(i.regs[regA]), uint32(i.regs[regB])
	if rhs == 0 {
		i.regs[dst] = sext(uint64(lhs), 4)
	} else {
		i.regs[dst] = sext(uint64(lhs%rhs), 4)
	}
	i.skip()
}

// RemS32 rem_s_32 φ′D =
// ⎧ 0			 		if a = −2^31 ∧ b = −1
// ⎨
// ⎩ Z−1_8 (smod(a, b)) otherwise
// where a = Z4(φA mod 2^32), b = Z4(φB mod 2^32)
func (i *Instance) RemS32(dst Reg, regA, regB Reg) {
	lhs := int32(uint32(i.regs[regA]))
	rhs := int32(uint32(i.regs[regB]))
	if lhs == math.MinInt32 && rhs == -1 {
		i.regs[dst] = uint64(0)
	} else {
		i.regs[dst] = uint64(smod32(lhs, rhs))
	}
	i.skip()
}

// ShloL32 shlo_l_32 φ′D = X4((φA ⋅ 2φB mod 32) mod 2^32)
func (i *Instance) ShloL32(dst Reg, regA, regB Reg) {
	i.setAndSkip(dst, sext(uint64(uint32(i.regs[regA])<<(uint32(i.regs[regB])%32)), 4))
}

// ShloR32 shlo_r_32 φ′D = X4(⌊ (φA mod 2^32) ÷ 2φB mod 32 ⌋)
func (i *Instance) ShloR32(dst Reg, regA, regB Reg) {
	i.setAndSkip(dst, sext(uint64(uint32(i.regs[regA])>>(uint32(i.regs[regB])%32)), 4))
}

// SharR32 shar_r_32 φ′D = Z−1_8(⌊ Z4(φA mod 2^32) ÷ 2φB mod 32 ⌋)
func (i *Instance) SharR32(dst Reg, regA, regB Reg) {
	shiftAmount := uint32(i.regs[regB]) % 32
	shiftedValue := int32(uint32(i.regs[regA])) >> shiftAmount
	i.setAndSkip(dst, uint64(shiftedValue))
}

// Add64 add_64 φ′D = (φA + φB) mod 2^64
func (i *Instance) Add64(dst Reg, regA, regB Reg) {
	i.setAndSkip(dst, i.regs[regA]+i.regs[regB])
}

// Sub64 sub_64 φ′D = (φA + 2^64 − φB) mod 2^64
func (i *Instance) Sub64(dst Reg, regA, regB Reg) {
	i.setAndSkip(dst, i.regs[regA]-i.regs[regB])
}

// Mul64 mul_64 φ′D = (φA ⋅ φB) mod 2^64
func (i *Instance) Mul64(dst Reg, regA, regB Reg) {
	i.setAndSkip(dst, i.regs[regA]*i.regs[regB])
}

// DivU64 div_u_64 φ′D = 2^64 − 1 if φB = 0 otherwise ⌊ φA ÷ φB ⌋
func (i *Instance) DivU64(dst Reg, regA, regB Reg) {
	lhs, rhs := i.regs[regA], i.regs[regB]
	if rhs == 0 {
		i.regs[dst] = math.MaxUint64
	} else {
		i.regs[dst] = lhs / rhs
	}
	i.skip()
}

// DivS64 div_s_64 φ′D =
// ⎧ 2^64 − 1 						if φB = 0
// ⎨ φA								if Z8(φA) = −2^63 ∧ Z8(φB) = −1
// ⎩ Z−1_8(rtz(Z8(φA) ÷ Z8(φB))) 	otherwise
func (i *Instance) DivS64(dst Reg, regA, regB Reg) {
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

// RemU64 rem_u_64 φ′D = φA if φB = 0 otherwise φA mod φB
func (i *Instance) RemU64(dst Reg, regA, regB Reg) {
	lhs, rhs := i.regs[regA], i.regs[regB]
	if rhs == 0 {
		i.regs[dst] = lhs
	} else {
		i.regs[dst] = lhs % rhs
	}
	i.skip()
}

// RemS64 rem_s_64 φ′D =
// ⎧ φA						 	 if φB = 0
// ⎨ 0 							 if Z8(φA) = −2^63 ∧ Z8(φB) = −1
// ⎩ Z−1_8(smod(Z8(φA), Z8(φB))) otherwise
func (i *Instance) RemS64(dst Reg, regA, regB Reg) {
	lhs, rhs := int64(i.regs[regA]), int64(i.regs[regB])
	if lhs == math.MinInt64 && rhs == -1 {
		i.regs[dst] = 0
	} else {
		i.regs[dst] = uint64(smod64(lhs, rhs))
	}
	i.skip()
}

// ShloL64 shlo_l_64 φ′D = (φA ⋅ 2φB mod 64) mod 2^64
func (i *Instance) ShloL64(dst Reg, regA, regB Reg) {
	shiftAmount := i.regs[regB] % 64
	shiftedValue := i.regs[regA] << shiftAmount
	i.setAndSkip(dst, shiftedValue)
}

// ShloR64 shlo_r_64 φ′D = ⌊ φA ÷ 2φB mod 64 ⌋
func (i *Instance) ShloR64(dst Reg, regA, regB Reg) {
	i.setAndSkip(dst, i.regs[regA]>>(i.regs[regB]%64))
}

// SharR64 shar_r_64 φ′D = Z−1_8(⌊ Z8(φA) ÷ 2φB mod 64 ⌋)
func (i *Instance) SharR64(dst Reg, regA, regB Reg) {
	shiftAmount := i.regs[regB] % 64
	shiftedValue := int64(i.regs[regA]) >> shiftAmount
	i.setAndSkip(dst, uint64(shiftedValue))
}

// And and ∀i ∈ N64 ∶ B8(φ′D)_i = B8(φA)_i ∧ B8(φB)_i
func (i *Instance) And(dst Reg, regA, regB Reg) {
	i.setAndSkip(dst, i.regs[regA]&i.regs[regB])
}

// Xor xor ∀i ∈ N64 ∶ B8(φ′D)_i = B8(φA)_i ⊕ B8(φB)_i
func (i *Instance) Xor(dst Reg, regA, regB Reg) {
	i.setAndSkip(dst, i.regs[regA]^i.regs[regB])
}

// Or or ∀i ∈ N64 ∶ B8(φ′D)_i = B8(φA)_i ∨ B8(φB)_i
func (i *Instance) Or(dst Reg, regA, regB Reg) {
	i.setAndSkip(dst, i.regs[regA]|i.regs[regB])
}

// MulUpperSS mul_upper_s_s φ′D = Z−1_8(⌊ (Z8(φA) ⋅ Z8(φB)) ÷ 2^64 ⌋)
func (i *Instance) MulUpperSS(dst Reg, regA, regB Reg) {
	lhs := big.NewInt(int64(i.regs[regA]))
	rhs := big.NewInt(int64(i.regs[regB]))
	mul := lhs.Mul(lhs, rhs)
	i.setAndSkip(dst, uint64(mul.Rsh(mul, 64).Int64()))
}

// MulUpperUU mul_upper_u_u φ′D = ⌊ (φA ⋅ φB ) ÷ 2^64 ⌋
func (i *Instance) MulUpperUU(dst Reg, regA, regB Reg) {
	lhs := (&big.Int{}).SetUint64(i.regs[regA])
	rhs := (&big.Int{}).SetUint64(i.regs[regB])
	mul := lhs.Mul(lhs, rhs)
	i.setAndSkip(dst, uint64(mul.Rsh(mul, 64).Int64()))
}

// MulUpperSU mul_upper_s_u φ′D = Z−1_8(⌊ (Z8(φA) ⋅ φB) ÷ 2^64 ⌋)
func (i *Instance) MulUpperSU(dst Reg, regA, regB Reg) {
	lhs := big.NewInt(int64(i.regs[regA]))
	rhs := (&big.Int{}).SetUint64(i.regs[regB])
	mul := lhs.Mul(lhs, rhs)
	i.setAndSkip(dst, uint64(mul.Rsh(mul, 64).Int64()))
}

// SetLtU set_lt_u φ′D = φA < φB
func (i *Instance) SetLtU(dst Reg, regA, regB Reg) {
	i.setAndSkip(dst, bool2uint64(i.regs[regA] < i.regs[regB]))
}

// SetLtS set_lt_s φ′D = Z8(φA) < Z8(φB)
func (i *Instance) SetLtS(dst Reg, regA, regB Reg) {
	i.setAndSkip(dst, bool2uint64(int64(i.regs[regA]) < int64(i.regs[regB])))
}

// CmovIz cmov_iz φ′D = φA if φB = 0 otherwise φD
func (i *Instance) CmovIz(dst Reg, s, c Reg) {
	if i.regs[c] == 0 {
		i.regs[dst] = i.regs[s]
	}
	i.skip()
}

// CmovNz cmov_nz φ′D = φA if φB ≠ 0 otherwise φD
func (i *Instance) CmovNz(dst Reg, s, c Reg) {
	if i.regs[c] != 0 {
		i.regs[dst] = i.regs[s]
	}
	i.skip()
}

// RotateLeft64 rot_l_64 ∀i ∈ N64 ∶ B8(φ′D)_{(i+φB) mod 64} = B8(φA)_i
func (i *Instance) RotateLeft64(dst Reg, regA, regB Reg) {
	i.setAndSkip(dst, bits.RotateLeft64(i.regs[regA], int(i.regs[regB])))
}

// RotateLeft32 rot_l_32 φ′D = X4(x) where x ∈ N2^32, ∀i ∈ N32 ∶ B4(x)_{(i+φB) mod 32} = B4(φA)_i
func (i *Instance) RotateLeft32(dst Reg, regA, regB Reg) {
	i.setAndSkip(dst, sext(uint64(bits.RotateLeft32(uint32(i.regs[regA]), int(i.regs[regB]))), 4))
}

// RotateRight64 rot_r_64 ∀i ∈ N64 ∶ B8(φ′D)_i = B8(φA)_{(i+φB ) mod 64}
func (i *Instance) RotateRight64(dst Reg, regA, regB Reg) {
	i.setAndSkip(dst, bits.RotateLeft64(i.regs[regA], -int(i.regs[regB])))
}

// RotateRight32 rot_r_32 φ′D = X4(x) where x ∈ N2^32, ∀i ∈ N32 ∶ B4(x)_i = B4(φA)_{(i+φB) mod 32}
func (i *Instance) RotateRight32(dst Reg, regA, regB Reg) {
	i.setAndSkip(dst, sext(uint64(bits.RotateLeft32(uint32(i.regs[regA]), -int(i.regs[regB]))), 4))
}

// AndInverted and_inv ∀i ∈ N64 ∶ B8(φ′D)_i = B8(φA)i ∧ ¬B8(φB)_i
func (i *Instance) AndInverted(dst Reg, regA, regB Reg) {
	i.setAndSkip(dst, i.regs[regA]&^i.regs[regB])
}

// OrInverted or_inv ∀i ∈ N64 ∶ B8(φ′D)_i = B8(φA)i ∨ ¬B8(φB)_i
func (i *Instance) OrInverted(dst Reg, regA, regB Reg) {
	i.setAndSkip(dst, i.regs[regA]|^i.regs[regB])
}

// Xnor xnor ∀i ∈ N64 ∶ B8(φ′D)_i = ¬(B8(φA)_i ⊕ B8(φB)_i)
func (i *Instance) Xnor(dst Reg, regA, regB Reg) {
	i.setAndSkip(dst, ^(i.regs[regA] ^ i.regs[regB]))
}

// Max max φ′D = Z−1_8(max(Z8(φA), Z8(φB)))
func (i *Instance) Max(dst Reg, regA, regB Reg) {
	i.setAndSkip(dst, uint64(max(int64(i.regs[regA]), int64(i.regs[regB]))))
}

// MaxUnsigned max_u φ′D = max(φA, φB)
func (i *Instance) MaxUnsigned(dst Reg, regA, regB Reg) {
	i.setAndSkip(dst, max(i.regs[regA], i.regs[regB]))
}

// Min min φ′D = Z8^-1(min(Z8(φA), Z8(φB)))
func (i *Instance) Min(dst Reg, regA, regB Reg) {
	i.setAndSkip(dst, uint64(min(int64(i.regs[regA]), int64(i.regs[regB]))))
}

// MinUnsigned min_u φ′D = min(φA, φB)
func (i *Instance) MinUnsigned(dst Reg, regA, regB Reg) {
	i.setAndSkip(dst, min(i.regs[regA], i.regs[regB]))
}

func bool2uint64(v bool) uint64 {
	if v {
		return 1
	}
	return 0
}

// smod (a Z, b Z) → Z a if b = 0 otherwise sgn(a)(|a| mod |b|) (eq. A.33 v0.7.2)
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

// smod (a Z, b Z) → Z a if b = 0 otherwise sgn(a)(|a| mod |b|) (eq. A.33 v0.7.2)
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
