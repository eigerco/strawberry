package interpreter

import (
	"github.com/eigerco/strawberry/internal/polkavm"
	"github.com/eigerco/strawberry/pkg/serialization/codec/jam"
)

// step Ψ1(B, B, ⟦NR⟧, NR, NG, ⟦NR⟧13, M) → ({☇, ∎, ▸} ∪ {F,-h} × NR, NR, ZG, ⟦NR⟧13, M) (A.6 v0.7.2)
func (i *Instance) step() (uint64, error) {
	codeLength := uint64(len(i.code))
	// ℓ ≡ skip(ı) (eq. A.20 v0.7.2)
	i.skipLen = polkavm.Skip(i.instructionCounter, i.bitmask)

	// ζ ≡ c ⌢ [0, 0, ... ] (eq. A.4 v0.7.2)
	// We cannot add infinite items to a slice, but we simulate this by defaulting to trap opcode
	opcode := polkavm.Trap

	if i.instructionCounter < codeLength {
		opcode = polkavm.Opcode(i.code[i.instructionCounter])
	}

	// ϱ′ = ϱ − ϱ∆ (eq. A.9 v0.7.2)
	if err := i.deductGas(polkavm.GasCosts[opcode]); err != nil {
		return 0, err
	}

	switch opcode {
	case polkavm.Trap:
		return 0, i.Trap()
	case polkavm.Fallthrough:
		i.Fallthrough()

	// (eq. A.21 v0.7.0)
	case polkavm.Ecalli:
		// ε = ħ × νX
		return i.decodeArgsImm(), polkavm.ErrHostCall

	// (eq. A.22 v0.7.0)
	case polkavm.LoadImm64:
		i.LoadImm64(i.decodeArgsRegImmExt())

	// (eq. A.23 v0.7.0)
	case polkavm.StoreImmU8:
		return 0, i.StoreImmU8(i.decodeArgsImm2())
	case polkavm.StoreImmU16:
		return 0, i.StoreImmU16(i.decodeArgsImm2())
	case polkavm.StoreImmU32:
		return 0, i.StoreImmU32(i.decodeArgsImm2())
	case polkavm.StoreImmU64:
		return 0, i.StoreImmU64(i.decodeArgsImm2())

	// (eq. A.24 v0.7.0)
	case polkavm.Jump:
		return 0, i.Jump(i.decodeArgsOffset())

	// (eq. A.25 v0.7.0)
	case polkavm.JumpIndirect:
		return 0, i.JumpIndirect(i.decodeArgsRegImm())
	case polkavm.LoadImm:
		i.LoadImm(i.decodeArgsRegImm())
	case polkavm.LoadU8:
		return 0, i.LoadU8(i.decodeArgsRegImm())
	case polkavm.LoadI8:
		return 0, i.LoadI8(i.decodeArgsRegImm())
	case polkavm.LoadU16:
		return 0, i.LoadU16(i.decodeArgsRegImm())
	case polkavm.LoadI16:
		return 0, i.LoadI16(i.decodeArgsRegImm())
	case polkavm.LoadU32:
		return 0, i.LoadU32(i.decodeArgsRegImm())
	case polkavm.LoadI32:
		return 0, i.LoadI32(i.decodeArgsRegImm())
	case polkavm.LoadU64:
		return 0, i.LoadU64(i.decodeArgsRegImm())
	case polkavm.StoreU8:
		return 0, i.StoreU8(i.decodeArgsRegImm())
	case polkavm.StoreU16:
		return 0, i.StoreU16(i.decodeArgsRegImm())
	case polkavm.StoreU32:
		return 0, i.StoreU32(i.decodeArgsRegImm())
	case polkavm.StoreU64:
		return 0, i.StoreU64(i.decodeArgsRegImm())

	// (eq. A.26 v0.7.0)
	case polkavm.StoreImmIndirectU8:
		return 0, i.StoreImmIndirectU8(i.decodeArgsRegImm2())
	case polkavm.StoreImmIndirectU16:
		return 0, i.StoreImmIndirectU16(i.decodeArgsRegImm2())
	case polkavm.StoreImmIndirectU32:
		return 0, i.StoreImmIndirectU32(i.decodeArgsRegImm2())
	case polkavm.StoreImmIndirectU64:
		return 0, i.StoreImmIndirectU64(i.decodeArgsRegImm2())

	// (eq. A.27 v0.7.0)
	case polkavm.LoadImmAndJump:
		return 0, i.LoadImmAndJump(i.decodeArgsRegImmOffset())
	case polkavm.BranchEqImm:
		return 0, i.BranchEqImm(i.decodeArgsRegImmOffset())
	case polkavm.BranchNotEqImm:
		return 0, i.BranchNotEqImm(i.decodeArgsRegImmOffset())
	case polkavm.BranchLessUnsignedImm:
		return 0, i.BranchLessUnsignedImm(i.decodeArgsRegImmOffset())
	case polkavm.BranchLessOrEqualUnsignedImm:
		return 0, i.BranchLessOrEqualUnsignedImm(i.decodeArgsRegImmOffset())
	case polkavm.BranchGreaterOrEqualUnsignedImm:
		return 0, i.BranchGreaterOrEqualUnsignedImm(i.decodeArgsRegImmOffset())
	case polkavm.BranchGreaterUnsignedImm:
		return 0, i.BranchGreaterUnsignedImm(i.decodeArgsRegImmOffset())
	case polkavm.BranchLessSignedImm:
		return 0, i.BranchLessSignedImm(i.decodeArgsRegImmOffset())
	case polkavm.BranchLessOrEqualSignedImm:
		return 0, i.BranchLessOrEqualSignedImm(i.decodeArgsRegImmOffset())
	case polkavm.BranchGreaterOrEqualSignedImm:
		return 0, i.BranchGreaterOrEqualSignedImm(i.decodeArgsRegImmOffset())
	case polkavm.BranchGreaterSignedImm:
		return 0, i.BranchGreaterSignedImm(i.decodeArgsRegImmOffset())

	// (eq. A.28 v0.7.0)
	case polkavm.MoveReg:
		i.MoveReg(i.decodeArgsReg2())
	case polkavm.Sbrk:
		return 0, i.Sbrk(i.decodeArgsReg2())
	case polkavm.CountSetBits64:
		i.CountSetBits64(i.decodeArgsReg2())
	case polkavm.CountSetBits32:
		i.CountSetBits32(i.decodeArgsReg2())
	case polkavm.LeadingZeroBits64:
		i.LeadingZeroBits64(i.decodeArgsReg2())
	case polkavm.LeadingZeroBits32:
		i.LeadingZeroBits32(i.decodeArgsReg2())
	case polkavm.TrailingZeroBits64:
		i.TrailingZeroBits64(i.decodeArgsReg2())
	case polkavm.TrailingZeroBits32:
		i.TrailingZeroBits32(i.decodeArgsReg2())
	case polkavm.SignExtend8:
		i.SignExtend8(i.decodeArgsReg2())
	case polkavm.SignExtend16:
		i.SignExtend16(i.decodeArgsReg2())
	case polkavm.ZeroExtend16:
		i.ZeroExtend16(i.decodeArgsReg2())
	case polkavm.ReverseBytes:
		i.ReverseBytes(i.decodeArgsReg2())

	// (eq. A.29 v0.7.0)
	case polkavm.StoreIndirectU8:
		return 0, i.StoreIndirectU8(i.decodeArgsReg2Imm())
	case polkavm.StoreIndirectU16:
		return 0, i.StoreIndirectU16(i.decodeArgsReg2Imm())
	case polkavm.StoreIndirectU32:
		return 0, i.StoreIndirectU32(i.decodeArgsReg2Imm())
	case polkavm.StoreIndirectU64:
		return 0, i.StoreIndirectU64(i.decodeArgsReg2Imm())
	case polkavm.LoadIndirectU8:
		return 0, i.LoadIndirectU8(i.decodeArgsReg2Imm())
	case polkavm.LoadIndirectI8:
		return 0, i.LoadIndirectI8(i.decodeArgsReg2Imm())
	case polkavm.LoadIndirectU16:
		return 0, i.LoadIndirectU16(i.decodeArgsReg2Imm())
	case polkavm.LoadIndirectI16:
		return 0, i.LoadIndirectI16(i.decodeArgsReg2Imm())
	case polkavm.LoadIndirectU32:
		return 0, i.LoadIndirectU32(i.decodeArgsReg2Imm())
	case polkavm.LoadIndirectI32:
		return 0, i.LoadIndirectI32(i.decodeArgsReg2Imm())
	case polkavm.LoadIndirectU64:
		return 0, i.LoadIndirectU64(i.decodeArgsReg2Imm())
	case polkavm.AddImm32:
		i.AddImm32(i.decodeArgsReg2Imm())
	case polkavm.AndImm:
		i.AndImm(i.decodeArgsReg2Imm())
	case polkavm.XorImm:
		i.XorImm(i.decodeArgsReg2Imm())
	case polkavm.OrImm:
		i.OrImm(i.decodeArgsReg2Imm())
	case polkavm.MulImm32:
		i.MulImm32(i.decodeArgsReg2Imm())
	case polkavm.SetLessThanUnsignedImm:
		i.SetLessThanUnsignedImm(i.decodeArgsReg2Imm())
	case polkavm.SetLessThanSignedImm:
		i.SetLessThanSignedImm(i.decodeArgsReg2Imm())
	case polkavm.ShiftLogicalLeftImm32:
		i.ShiftLogicalLeftImm32(i.decodeArgsReg2Imm())
	case polkavm.ShiftLogicalRightImm32:
		i.ShiftLogicalRightImm32(i.decodeArgsReg2Imm())
	case polkavm.ShiftArithmeticRightImm32:
		i.ShiftArithmeticRightImm32(i.decodeArgsReg2Imm())
	case polkavm.NegateAndAddImm32:
		i.NegateAndAddImm32(i.decodeArgsReg2Imm())
	case polkavm.SetGreaterThanUnsignedImm:
		i.SetGreaterThanUnsignedImm(i.decodeArgsReg2Imm())
	case polkavm.SetGreaterThanSignedImm:
		i.SetGreaterThanSignedImm(i.decodeArgsReg2Imm())
	case polkavm.ShiftLogicalLeftImmAlt32:
		i.ShiftLogicalLeftImmAlt32(i.decodeArgsReg2Imm())
	case polkavm.ShiftArithmeticRightImmAlt32:
		i.ShiftLogicalRightImmAlt32(i.decodeArgsReg2Imm())
	case polkavm.ShiftLogicalRightImmAlt32:
		i.ShiftArithmeticRightImmAlt32(i.decodeArgsReg2Imm())
	case polkavm.CmovIfZeroImm:
		i.CmovIfZeroImm(i.decodeArgsReg2Imm())
	case polkavm.CmovIfNotZeroImm:
		i.CmovIfNotZeroImm(i.decodeArgsReg2Imm())
	case polkavm.AddImm64:
		i.AddImm64(i.decodeArgsReg2Imm())
	case polkavm.MulImm64:
		i.MulImm64(i.decodeArgsReg2Imm())
	case polkavm.ShiftLogicalLeftImm64:
		i.ShiftLogicalLeftImm64(i.decodeArgsReg2Imm())
	case polkavm.ShiftLogicalRightImm64:
		i.ShiftLogicalRightImm64(i.decodeArgsReg2Imm())
	case polkavm.ShiftArithmeticRightImm64:
		i.ShiftArithmeticRightImm64(i.decodeArgsReg2Imm())
	case polkavm.NegateAndAddImm64:
		i.NegateAndAddImm64(i.decodeArgsReg2Imm())
	case polkavm.ShiftLogicalLeftImmAlt64:
		i.ShiftLogicalLeftImmAlt64(i.decodeArgsReg2Imm())
	case polkavm.ShiftLogicalRightImmAlt64:
		i.ShiftLogicalRightImmAlt64(i.decodeArgsReg2Imm())
	case polkavm.ShiftArithmeticRightImmAlt64:
		i.ShiftArithmeticRightImmAlt64(i.decodeArgsReg2Imm())
	case polkavm.RotR64Imm:
		i.RotateRight64Imm(i.decodeArgsReg2Imm())
	case polkavm.RotR64ImmAlt:
		i.RotateRight64ImmAlt(i.decodeArgsReg2Imm())
	case polkavm.RotR32Imm:
		i.RotateRight32Imm(i.decodeArgsReg2Imm())
	case polkavm.RotR32ImmAlt:
		i.RotateRight32ImmAlt(i.decodeArgsReg2Imm())

	// (eq. A.30 v0.7.0)
	case polkavm.BranchEq:
		return 0, i.BranchEq(i.decodeArgsReg2Offset())
	case polkavm.BranchNotEq:
		return 0, i.BranchNotEq(i.decodeArgsReg2Offset())
	case polkavm.BranchLessUnsigned:
		return 0, i.BranchLessUnsigned(i.decodeArgsReg2Offset())
	case polkavm.BranchLessSigned:
		return 0, i.BranchLessSigned(i.decodeArgsReg2Offset())
	case polkavm.BranchGreaterOrEqualUnsigned:
		return 0, i.BranchGreaterOrEqualUnsigned(i.decodeArgsReg2Offset())
	case polkavm.BranchGreaterOrEqualSigned:
		return 0, i.BranchGreaterOrEqualSigned(i.decodeArgsReg2Offset())

	// (eq. A.31 v0.7.0)
	case polkavm.LoadImmAndJumpIndirect:
		return 0, i.LoadImmAndJumpIndirect(i.decodeArgsReg2Imm2())

	// (eq. A.32 v0.7.0)
	case polkavm.Add32:
		i.Add32(i.decodeArgsReg3())
	case polkavm.Sub32:
		i.Sub32(i.decodeArgsReg3())
	case polkavm.Mul32:
		i.Mul32(i.decodeArgsReg3())
	case polkavm.DivUnsigned32:
		i.DivUnsigned32(i.decodeArgsReg3())
	case polkavm.DivSigned32:
		i.DivSigned32(i.decodeArgsReg3())
	case polkavm.RemUnsigned32:
		i.RemUnsigned32(i.decodeArgsReg3())
	case polkavm.RemSigned32:
		i.RemSigned32(i.decodeArgsReg3())
	case polkavm.ShiftLogicalLeft32:
		i.ShiftLogicalLeft32(i.decodeArgsReg3())
	case polkavm.ShiftLogicalRight32:
		i.ShiftLogicalRight32(i.decodeArgsReg3())
	case polkavm.ShiftArithmeticRight32:
		i.ShiftArithmeticRight32(i.decodeArgsReg3())
	case polkavm.Add64:
		i.Add64(i.decodeArgsReg3())
	case polkavm.Sub64:
		i.Sub64(i.decodeArgsReg3())
	case polkavm.Mul64:
		i.Mul64(i.decodeArgsReg3())
	case polkavm.DivUnsigned64:
		i.DivUnsigned64(i.decodeArgsReg3())
	case polkavm.DivSigned64:
		i.DivSigned64(i.decodeArgsReg3())
	case polkavm.RemUnsigned64:
		i.RemUnsigned64(i.decodeArgsReg3())
	case polkavm.RemSigned64:
		i.RemSigned64(i.decodeArgsReg3())
	case polkavm.ShiftLogicalLeft64:
		i.ShiftLogicalLeft64(i.decodeArgsReg3())
	case polkavm.ShiftLogicalRight64:
		i.ShiftLogicalRight64(i.decodeArgsReg3())
	case polkavm.ShiftArithmeticRight64:
		i.ShiftArithmeticRight64(i.decodeArgsReg3())
	case polkavm.And:
		i.And(i.decodeArgsReg3())
	case polkavm.Xor:
		i.Xor(i.decodeArgsReg3())
	case polkavm.Or:
		i.Or(i.decodeArgsReg3())
	case polkavm.MulUpperSignedSigned:
		i.MulUpperSignedSigned(i.decodeArgsReg3())
	case polkavm.MulUpperUnsignedUnsigned:
		i.MulUpperUnsignedUnsigned(i.decodeArgsReg3())
	case polkavm.MulUpperSignedUnsigned:
		i.MulUpperSignedUnsigned(i.decodeArgsReg3())
	case polkavm.SetLessThanUnsigned:
		i.SetLessThanUnsigned(i.decodeArgsReg3())
	case polkavm.SetLessThanSigned:
		i.SetLessThanSigned(i.decodeArgsReg3())
	case polkavm.CmovIfZero:
		i.CmovIfZero(i.decodeArgsReg3())
	case polkavm.CmovIfNotZero:
		i.CmovIfNotZero(i.decodeArgsReg3())
	case polkavm.RotL64:
		i.RotateLeft64(i.decodeArgsReg3())
	case polkavm.RotL32:
		i.RotateLeft32(i.decodeArgsReg3())
	case polkavm.RotR64:
		i.RotateRight64(i.decodeArgsReg3())
	case polkavm.RotR32:
		i.RotateRight32(i.decodeArgsReg3())
	case polkavm.AndInv:
		i.AndInverted(i.decodeArgsReg3())
	case polkavm.OrInv:
		i.OrInverted(i.decodeArgsReg3())
	case polkavm.Xnor:
		i.Xnor(i.decodeArgsReg3())
	case polkavm.Max:
		i.Max(i.decodeArgsReg3())
	case polkavm.MaxU:
		i.MaxUnsigned(i.decodeArgsReg3())
	case polkavm.Min:
		i.Min(i.decodeArgsReg3())
	case polkavm.MinU:
		i.MinUnsigned(i.decodeArgsReg3())
	default:
		// c_n if kn = 1 ∧ cn ∈ U otherwise 0 (eq. A.19 v0.7.2)
		return 0, i.Trap()
	}
	return 0, nil
}

// Zn∈N∶ N28n → Z_−2^8n−1...2^8n−1 (eq. A.10 v0.7.2)
func signed(value uint64, length uint64) int64 {
	switch length {
	case 0:
		return 0
	case 1:
		return int64(int8(value))
	case 2:
		return int64(int16(value))
	case 3:
		return int64(int32(value<<8)) >> 8
	case 4:
		return int64(int32(value))
	case 8:
		return int64(value)
	default:
		panic("unreachable")
	}
}

// Xn∈{0,1,2,3,4,8}∶ N^28n → N_R (eq. A.16 v0.7.2)
func sext(value uint64, length uint64) uint64 {
	if length == 0 {
		return 0
	}
	if length > 8 {
		panic("unsupported bit length")
	}

	numBits := length * 8

	if numBits == 64 {
		return uint64(int64(value))
	}

	mask := uint64((1 << numBits) - 1)

	relevantValue := value & mask
	signBit := uint64(1) << (numBits - 1)

	if (relevantValue & signBit) != 0 {
		return relevantValue | (^mask)
	} else {
		return relevantValue
	}
}

func (i *Instance) decodeArgsImm() (valueX uint64) {
	if instr, ok := i.instructionsCache[i.instructionCounter]; ok {
		return instr.val[0]
	}
	// let lX = min(4, ℓ)
	lenX := min(4, i.skipLen)

	// νX ≡ X_lX(E−1lX (ζı+1⋅⋅⋅+lX))
	valueX = sext(jam.DecodeUint64(i.code[i.instructionCounter+1:i.instructionCounter+1+lenX]), lenX)
	i.instructionsCache[i.instructionCounter] = instructionCache{val: [2]uint64{valueX}}
	return valueX
}

func (i *Instance) decodeArgsRegImmExt() (regA polkavm.Reg, valueX uint64) {
	if instr, ok := i.instructionsCache[i.instructionCounter]; ok {
		return instr.reg[0], instr.val[0]
	}
	// let rA = min(12, ζı+1 mod 16), φ′A ≡ φ′rA
	regA = polkavm.Reg(min(12, i.code[i.instructionCounter+1]%16))
	// νX ≡ E−1_8(ζı+2⋅⋅⋅+8)
	valueX = jam.DecodeUint64(i.code[i.instructionCounter+2 : i.instructionCounter+10])
	i.instructionsCache[i.instructionCounter] = instructionCache{reg: [3]polkavm.Reg{regA}, val: [2]uint64{valueX}}
	return regA, valueX
}

func (i *Instance) decodeArgsImm2() (valueX, valueY uint64) {
	if instr, ok := i.instructionsCache[i.instructionCounter]; ok {
		return instr.val[0], instr.val[1]
	}
	// let lX = min(4, ζı+1 mod 8)
	lenX := uint64(min(4, i.code[i.instructionCounter+1]%8))

	// let lY = min(4, max(0, ℓ − lX − 1))
	lenY := uint64(min(4, max(0, int(i.skipLen)-int(lenX)-1)))

	// νX ≡ X_lX (E−1lX (ζı+2⋅⋅⋅+lX))
	valueX = sext(jam.DecodeUint64(i.code[i.instructionCounter+2:i.instructionCounter+2+lenX]), lenX)

	// νY ≡ XlY (E−1lY (ζı+2+lX ⋅⋅⋅+lY))
	valueY = sext(jam.DecodeUint64(i.code[i.instructionCounter+2+lenX:i.instructionCounter+2+lenX+lenY]), lenY)
	i.instructionsCache[i.instructionCounter] = instructionCache{val: [2]uint64{valueX, valueY}}
	return valueX, valueY
}

func (i *Instance) decodeArgsOffset() (valueX uint64) {
	if instr, ok := i.instructionsCache[i.instructionCounter]; ok {
		return instr.val[0]
	}
	// let lX = min(4, ℓ)
	lenX := min(4, i.skipLen)

	// νX ≡ ı + Z_lX (E−1_lX(ζı+1⋅⋅⋅+lX))
	valueX = uint64(int64(i.instructionCounter) + signed(jam.DecodeUint64(i.code[i.instructionCounter+1:i.instructionCounter+1+lenX]), lenX))
	i.instructionsCache[i.instructionCounter] = instructionCache{val: [2]uint64{valueX}}
	return valueX
}

func (i *Instance) decodeArgsRegImm() (regA polkavm.Reg, valueX uint64) {
	if instr, ok := i.instructionsCache[i.instructionCounter]; ok {
		return instr.reg[0], instr.val[0]
	}
	// let lX = min(4, max(0, ℓ − 1))
	lenX := uint64(min(4, max(0, int(i.skipLen)-1)))
	// let rA = min(12, ζı+1 mod 16), φ′A ≡ φ′rA
	regA = polkavm.Reg(min(12, i.code[i.instructionCounter+1]%16))

	// νX ≡ X_lX(E−1_lX(ζı+2...+lX))
	valueX = sext(jam.DecodeUint64(i.code[i.instructionCounter+2:i.instructionCounter+2+lenX]), lenX)
	i.instructionsCache[i.instructionCounter] = instructionCache{reg: [3]polkavm.Reg{regA}, val: [2]uint64{valueX}}
	return regA, valueX
}

func (i *Instance) decodeArgsRegImm2() (regA polkavm.Reg, valueX, valueY uint64) {
	if instr, ok := i.instructionsCache[i.instructionCounter]; ok {
		return instr.reg[0], instr.val[0], instr.val[1]
	}
	// let rA = min(12, ζı+1 mod 16), φA ≡ φrA, φ′A ≡ φ′rA
	regA = polkavm.Reg(min(12, i.code[i.instructionCounter+1]%16))
	// let lX = min(4, ⌊ ζı+1 / 16 ⌋ mod 8)
	lenX := uint64(min(4, (i.code[i.instructionCounter+1]/16)%8))

	// let lY = min(4, max(0, ℓ − lX − 1))
	lenY := uint64(min(4, max(0, int(i.skipLen)-int(lenX)-1)))

	// νX = X_lX (E−1lX (ζı+2⋅⋅⋅+lX))
	valueX = sext(jam.DecodeUint64(i.code[i.instructionCounter+2:i.instructionCounter+2+lenX]), lenX)

	// νY = X_lY(E−1lY (ζı+2+lX ⋅⋅⋅+lY))
	valueY = sext(jam.DecodeUint64(i.code[i.instructionCounter+2+lenX:i.instructionCounter+2+lenX+lenY]), lenY)
	i.instructionsCache[i.instructionCounter] = instructionCache{reg: [3]polkavm.Reg{regA}, val: [2]uint64{valueX, valueY}}
	return regA, valueX, valueY
}

func (i *Instance) decodeArgsRegImmOffset() (regA polkavm.Reg, valueX, valueY uint64) {
	if instr, ok := i.instructionsCache[i.instructionCounter]; ok {
		return instr.reg[0], instr.val[0], instr.val[1]
	}
	// let rA = min(12, ζı+1 mod 16), φA ≡ φrA, φ′A ≡ φ′rA
	regA = polkavm.Reg(min(12, i.code[i.instructionCounter+1]%16))
	// let lX = min(4, ⌊ ζı+1 / 16 ⌋ mod 8)
	lenX := uint64(min(4, (i.code[i.instructionCounter+1]/16)%8))
	// let lY = min(4, max(0, ℓ − lX − 1))
	lenY := uint64(min(4, max(0, int(i.skipLen)-int(lenX)-1)))

	// νX = X_lX(E−1lX (ζı+2...+lX))
	valueX = sext(jam.DecodeUint64(i.code[i.instructionCounter+2:i.instructionCounter+2+lenX]), lenX)
	// νY = ı + ZlY(E−1lY (ζı+2+lX⋅⋅⋅+lY))
	valueY = uint64(int64(i.instructionCounter) + signed(jam.DecodeUint64(i.code[i.instructionCounter+2+lenX:i.instructionCounter+2+lenX+lenY]), lenY))
	i.instructionsCache[i.instructionCounter] = instructionCache{reg: [3]polkavm.Reg{regA}, val: [2]uint64{valueX, valueY}}
	return regA, valueX, valueY
}

func (i *Instance) decodeArgsReg2() (regDst, regA polkavm.Reg) {
	if instr, ok := i.instructionsCache[i.instructionCounter]; ok {
		return instr.reg[0], instr.reg[1]
	}
	// let rD = min(12, (ζı+1) mod 16) , φD ≡ φrD , φ′D ≡ φ′rD
	regDst = polkavm.Reg(min(12, i.code[i.instructionCounter+1]%16))

	// let rA = min(12, ⌊ ζı+1 / 16 ⌋) , φA ≡ φrA , φ′A ≡ φ′rA
	regA = polkavm.Reg(min(12, i.code[i.instructionCounter+1]/16))
	i.instructionsCache[i.instructionCounter] = instructionCache{reg: [3]polkavm.Reg{regDst, regA}}
	return regDst, regA
}

func (i *Instance) decodeArgsReg2Imm() (regA, regB polkavm.Reg, valueX uint64) {
	if instr, ok := i.instructionsCache[i.instructionCounter]; ok {
		return instr.reg[0], instr.reg[1], instr.val[0]
	}
	// let lX = min(4, max(0, ℓ − 1))
	lenX := uint64(min(4, max(0, int(i.skipLen)-1)))
	// let rA = min(12, (ζı+1) mod 16), φA ≡ φrA, φ′A ≡ φ′rA
	regA = polkavm.Reg(min(12, i.code[i.instructionCounter+1]%16))
	// let rB = min(12, ⌊ ζı+1 / 16 ⌋), φB ≡ φrB, φ′B ≡ φ′rB
	regB = polkavm.Reg(min(12, i.code[i.instructionCounter+1]/16))

	// νX ≡ X_lX(E−1lX(ζı+2...+lX))
	valueX = sext(jam.DecodeUint64(i.code[i.instructionCounter+2:i.instructionCounter+2+lenX]), lenX)
	i.instructionsCache[i.instructionCounter] = instructionCache{reg: [3]polkavm.Reg{regA, regB}, val: [2]uint64{valueX}}
	return regA, regB, valueX
}

func (i *Instance) decodeArgsReg2Offset() (regA, regB polkavm.Reg, valueX uint64) {
	if instr, ok := i.instructionsCache[i.instructionCounter]; ok {
		return instr.reg[0], instr.reg[1], instr.val[0]
	}
	// let lX = min(4, max(0, ℓ − 1))
	lenX := uint64(min(4, max(0, int(i.skipLen)-1)))
	// let rA = min(12, (ζı+1) mod 16), φA ≡ φrA, φ′A ≡ φ′rA
	regA = polkavm.Reg(min(12, i.code[i.instructionCounter+1]%16))
	// let rB = min(12, ⌊ ζı+1 / 16 ⌋), φB ≡ φrB, φ′B ≡ φ′rB
	regB = polkavm.Reg(min(12, i.code[i.instructionCounter+1]/16))

	// νX ≡ ı + Z_lX(E−1lX(ζı+2...+lX))
	valueX = uint64(int64(i.instructionCounter) + signed(jam.DecodeUint64(i.code[i.instructionCounter+2:i.instructionCounter+2+lenX]), lenX))
	i.instructionsCache[i.instructionCounter] = instructionCache{reg: [3]polkavm.Reg{regA, regB}, val: [2]uint64{valueX}}
	return regA, regB, valueX
}

func (i *Instance) decodeArgsReg2Imm2() (regA, regB polkavm.Reg, valueX, valueY uint64) {
	if instr, ok := i.instructionsCache[i.instructionCounter]; ok {
		return instr.reg[0], instr.reg[1], instr.val[0], instr.val[1]
	}
	// let rA = min(12, (ζı+1) mod 16), φA ≡ φrA, φ′A ≡ φ′rA
	regA = polkavm.Reg(min(12, i.code[i.instructionCounter+1]%16))
	// let rB = min(12, ⌊ ζı+1 / 16 ⌋), φB ≡ φrB, φ′B ≡ φ′rB
	regB = polkavm.Reg(min(12, i.code[i.instructionCounter+1]/16))
	// let lX = min(4, ζı+2 mod 8)
	lenX := uint64(min(4, i.code[i.instructionCounter+2]%8))
	// let lY = min(4, max(0, ℓ − lX − 2))
	lenY := uint64(min(4, max(0, int(i.skipLen)-int(lenX)-2)))

	// νX = X_lX(E−1lX (ζı+3⋅⋅⋅+lX))
	valueX = jam.DecodeUint64(i.code[i.instructionCounter+3 : i.instructionCounter+3+lenX])
	// vY = X_lY(E−1lY (ζı+3+lX ⋅⋅⋅+lY))
	valueY = sext(jam.DecodeUint64(i.code[i.instructionCounter+3+lenX:i.instructionCounter+3+lenX+lenY]), lenY)

	i.instructionsCache[i.instructionCounter] = instructionCache{reg: [3]polkavm.Reg{regA, regB}, val: [2]uint64{valueX, valueY}}
	return regA, regB, valueX, valueY
}

func (i *Instance) decodeArgsReg3() (regDst, regA, regB polkavm.Reg) {
	if instr, ok := i.instructionsCache[i.instructionCounter]; ok {
		return instr.reg[0], instr.reg[1], instr.reg[2]
	}
	// let rA = min(12, (ζı+1) mod 16), φA ≡ φrA, φ′A ≡ φ′rA
	regA = polkavm.Reg(min(12, i.code[i.instructionCounter+1]%16))
	// let rB = min(12, ⌊ ζı+1 / 16 ⌋), φB ≡ φrB, φ′B ≡ φ′rB
	regB = polkavm.Reg(min(12, i.code[i.instructionCounter+1]/16))
	// let rD = min(12, ζı+2), φD ≡ φrD, φ′D ≡ φ′rD
	regDst = polkavm.Reg(min(12, i.code[i.instructionCounter+2]))

	i.instructionsCache[i.instructionCounter] = instructionCache{reg: [3]polkavm.Reg{regDst, regA, regB}}
	return regDst, regA, regB
}
