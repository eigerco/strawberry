package interpreter

import (
	"github.com/eigerco/strawberry/internal/polkavm"
	"github.com/eigerco/strawberry/pkg/serialization/codec/jam"
)

// step Ψ1(Y, B, ⟦NR⟧, NR, NG, ⟦NR⟧13, M) → ({☇, ∎, ▸} ∪ {F ,̵ h} × NR, NR, ZG, _⟦NR⟧13, M)
func (i *Instance) step() (uint32, error) {
	codeLength := uint32(len(i.code))
	// ℓ ≡ skip(ı) (eq. A.18)
	skip := polkavm.Skip(i.instructionCounter, i.bitmask)

	// ζ_ı
	opcode := polkavm.Opcode(i.code[i.instructionCounter])

	if err := i.deductGas(polkavm.GasCosts[opcode]); err != nil {
		return 0, err
	}

	switch polkavm.InstructionForType[opcode] {
	case polkavm.InstrNone:
		switch opcode {
		case polkavm.Trap:
			return 0, i.Trap()
		case polkavm.Fallthrough:
			i.Fallthrough()
		default:
			return 0, polkavm.ErrPanicf("unexpected opcode %v", opcode)
		}
	case polkavm.InstrImm:
		// let lX = min(4, ℓ)
		lenX := min(4, skip)
		if codeLength < i.instructionCounter+1+lenX {
			return 0, polkavm.ErrPanicf("out of bound code access")
		}

		// νX ≡ X_lX(E−1lX (ζı+1⋅⋅⋅+lX))
		var valueX uint32
		err := jam.Unmarshal(i.code[i.instructionCounter+1:i.instructionCounter+1+lenX], &valueX)
		if err != nil {
			return 0, err
		}
		valueX = sext(valueX, lenX)
		switch opcode {
		case polkavm.Ecalli:
			// ε = ħ × νX
			return valueX, polkavm.ErrHostCall
		default:
			return 0, polkavm.ErrPanicf("unexpected opcode %v", opcode)
		}
	case polkavm.InstrRegImmExt:
		if codeLength < i.instructionCounter+10 {
			return 0, polkavm.ErrPanicf("out of bound code access")
		}
		// let rA = min(12, ζı+1 mod 16), ω′A ≡ ω′rA
		regA := min(12, i.code[i.instructionCounter+1]%16)
		// νX ≡ E−1_8(ζı+2⋅⋅⋅+8)
		valueX := uint64(0)
		if err := jam.Unmarshal(i.code[i.instructionCounter+2:i.instructionCounter+10], &valueX); err != nil {
			return 0, err
		}
		switch opcode {
		case polkavm.LoadImm64:
			i.LoadImm64(polkavm.Reg(regA), valueX)
		default:
			return 0, polkavm.ErrPanicf("unexpected opcode %v", opcode)
		}
	case polkavm.InstrImm2:
		if codeLength < i.instructionCounter+2 {
			return 0, polkavm.ErrPanicf("out of bound code access")
		}
		// let lX = min(4, ζı+1 mod 8)
		lenX := uint32(min(4, i.code[i.instructionCounter+1]%8))

		// let lY = min(4, max(0, ℓ − lX − 1))
		lenY := min(4, max(0, skip-lenX-1))

		if codeLength < i.instructionCounter+2+lenX+lenY {
			return 0, polkavm.ErrPanicf("out of bound code access")
		}

		// νX ≡ X_lX (E−1lX (ζı+2⋅⋅⋅+lX))
		valueX := uint32(0)
		if err := jam.Unmarshal(i.code[i.instructionCounter+2:i.instructionCounter+2+lenX], &valueX); err != nil {
			return 0, err
		}
		valueX = sext(valueX, lenX)

		// νY ≡ XlY (E−1lY (ζı+2+lX ⋅⋅⋅+lY))
		valueY := uint32(0)
		if err := jam.Unmarshal(i.code[i.instructionCounter+2+lenX:i.instructionCounter+2+lenX+lenY], &valueY); err != nil {
			return 0, err
		}
		valueY = sext(valueY, lenY)
		switch opcode {
		case polkavm.StoreImmU8:
			return 0, i.StoreImmU8(valueX, valueY)
		case polkavm.StoreImmU16:
			return 0, i.StoreImmU16(valueX, valueY)
		case polkavm.StoreImmU32:
			return 0, i.StoreImmU32(valueX, valueY)
		case polkavm.StoreImmU64:
			return 0, i.StoreImmU64(valueX, valueY)
		default:
			return 0, polkavm.ErrPanicf("unexpected opcode %v", opcode)
		}
	case polkavm.InstrOffset:
		// let lX = min(4, ℓ)
		lenX := min(4, skip)
		if codeLength < i.instructionCounter+1+lenX {
			return 0, polkavm.ErrPanicf("out of bound code access")
		}

		// νX ≡ ı + Z_lX (E−1lX (ζı+1⋅⋅⋅+lX))
		valueX := uint32(0)
		if err := jam.Unmarshal(i.code[i.instructionCounter+1:i.instructionCounter+1+lenX], &valueX); err != nil {
			return 0, err
		}
		valueX = i.instructionCounter + sext(valueX, lenX)

		switch opcode {
		case polkavm.Jump:
			return 0, i.Jump(valueX)
		default:
			return 0, polkavm.ErrPanicf("unexpected opcode %v", opcode)
		}
	case polkavm.InstrRegImm:
		// let lX = min(4, max(0, ℓ − 1))
		lenX := min(4, max(0, skip-1))
		if codeLength < i.instructionCounter+2+lenX {
			return 0, polkavm.ErrPanicf("out of bound code access")
		}
		// let rA = min(12, ζı+1 mod 16), ω′A ≡ ω′rA
		regA := polkavm.Reg(min(12, i.code[i.instructionCounter+1]%16))

		// νX ≡ E−1_8(ζı+2⋅⋅⋅+8)
		valueX := uint32(0)
		if err := jam.Unmarshal(i.code[i.instructionCounter+2:i.instructionCounter+2+lenX], &valueX); err != nil {
			return 0, err
		}
		valueX = sext(valueX, lenX)

		switch opcode {
		case polkavm.JumpIndirect:
			return 0, i.JumpIndirect(regA, valueX)
		case polkavm.LoadImm:
			i.LoadImm(regA, valueX)
		case polkavm.LoadU8:
			return 0, i.LoadU8(regA, valueX)
		case polkavm.LoadI8:
			return 0, i.LoadI8(regA, valueX)
		case polkavm.LoadU16:
			return 0, i.LoadU16(regA, valueX)
		case polkavm.LoadI16:
			return 0, i.LoadI16(regA, valueX)
		case polkavm.LoadU32:
			return 0, i.LoadU32(regA, valueX)
		case polkavm.LoadI32:
			return 0, i.LoadI32(regA, valueX)
		case polkavm.LoadU64:
			return 0, i.LoadU64(regA, valueX)
		case polkavm.StoreU8:
			return 0, i.StoreU8(regA, valueX)
		case polkavm.StoreU16:
			return 0, i.StoreU16(regA, valueX)
		case polkavm.StoreU32:
			return 0, i.StoreU32(regA, valueX)
		case polkavm.StoreU64:
			return 0, i.StoreU64(regA, valueX)
		default:
			return 0, polkavm.ErrPanicf("unexpected opcode %v", opcode)
		}
	case polkavm.InstrRegImm2:
		if codeLength < i.instructionCounter+2 {
			return 0, polkavm.ErrPanicf("out of bound code access")
		}

		// let rA = min(12, ζı+1 mod 16), ωA ≡ ωrA, ω′A ≡ ω′rA
		regA := polkavm.Reg(min(12, i.code[i.instructionCounter+1]%16))
		// let lX = min(4, ⌊ ζı+1 / 16 ⌋ mod 8)
		lenX := uint32(min(4, (i.code[i.instructionCounter+1]/16)%8))

		// let lY = min(4, max(0, ℓ − lX − 1))
		lenY := min(4, max(0, skip-lenX-1))

		if codeLength < i.instructionCounter+2+lenX+lenY {
			return 0, polkavm.ErrPanicf("out of bound code access")
		}

		// νX = X_lX (E−1lX (ζı+2⋅⋅⋅+lX))
		valueX := uint32(0)
		if err := jam.Unmarshal(i.code[i.instructionCounter+2:i.instructionCounter+2+lenX], &valueX); err != nil {
			return 0, err
		}
		valueX = sext(valueX, lenX)

		// νY = ı + ZlY (E−1lY (ζı+2+lX ⋅⋅⋅+lY))
		valueY := uint32(0)
		if err := jam.Unmarshal(i.code[i.instructionCounter+2+lenX:i.instructionCounter+2+lenX+lenY], &valueY); err != nil {
			return 0, err
		}
		valueX = sext(valueX, lenX)

		switch opcode {
		case polkavm.StoreImmIndirectU8:
			return 0, i.StoreImmIndirectU8(regA, valueX, valueY)
		case polkavm.StoreImmIndirectU16:
			return 0, i.StoreImmIndirectU16(regA, valueX, valueY)
		case polkavm.StoreImmIndirectU32:
			return 0, i.StoreImmIndirectU32(regA, valueX, valueY)
		case polkavm.StoreImmIndirectU64:
			return 0, i.StoreImmIndirectU64(regA, valueX, valueY)
		default:
			return 0, polkavm.ErrPanicf("unexpected opcode %v", opcode)
		}
	case polkavm.InstrRegImmOffset:
		if codeLength < i.instructionCounter+2 {
			return 0, polkavm.ErrPanicf("out of bound code access")
		}
		// let rA = min(12, ζı+1 mod 16), ωA ≡ ωrA, ω′A ≡ ω′rA
		regA := polkavm.Reg(min(12, i.code[i.instructionCounter+1]%16))
		// let lX = min(4, ⌊ ζı+1 / 16 ⌋ mod 8)
		lenX := uint32(min(4, (i.code[i.instructionCounter+1]/16)%8))
		// let lY = min(4, max(0, ℓ − lX − 1))
		lenY := min(4, max(0, skip-lenX-1))

		if codeLength < i.instructionCounter+2+lenX+lenY {
			return 0, polkavm.ErrPanicf("out of bound code access")
		}

		// νX = X_lX(E−1lX (ζı+2...+lX))
		valueX := uint32(0)
		if err := jam.Unmarshal(i.code[i.instructionCounter+2:i.instructionCounter+2+lenX], &valueX); err != nil {
			return 0, err
		}
		valueX = sext(valueX, lenX)
		// vY = X_lY(E−1lY (ζı+2+lX...+lY))
		valueY := uint32(0)
		if err := jam.Unmarshal(i.code[i.instructionCounter+2+lenX:i.instructionCounter+2+lenX+lenY], &valueY); err != nil {
			return 0, err
		}
		valueY = i.instructionCounter + sext(valueY, lenX)

		switch opcode {
		case polkavm.LoadImmAndJump:
			return 0, i.LoadImmAndJump(regA, valueX, valueY)
		case polkavm.BranchEqImm:
			return 0, i.BranchEqImm(regA, valueX, valueY)
		case polkavm.BranchNotEqImm:
			return 0, i.BranchNotEqImm(regA, valueX, valueY)
		case polkavm.BranchLessUnsignedImm:
			return 0, i.BranchLessUnsignedImm(regA, valueX, valueY)
		case polkavm.BranchLessOrEqualUnsignedImm:
			return 0, i.BranchLessOrEqualUnsignedImm(regA, valueX, valueY)
		case polkavm.BranchGreaterOrEqualUnsignedImm:
			return 0, i.BranchGreaterOrEqualUnsignedImm(regA, valueX, valueY)
		case polkavm.BranchGreaterUnsignedImm:
			return 0, i.BranchGreaterUnsignedImm(regA, valueX, valueY)
		case polkavm.BranchLessSignedImm:
			return 0, i.BranchLessSignedImm(regA, valueX, valueY)
		case polkavm.BranchLessOrEqualSignedImm:
			return 0, i.BranchLessOrEqualSignedImm(regA, valueX, valueY)
		case polkavm.BranchGreaterOrEqualSignedImm:
			return 0, i.BranchGreaterOrEqualSignedImm(regA, valueX, valueY)
		case polkavm.BranchGreaterSignedImm:
			return 0, i.BranchGreaterSignedImm(regA, valueX, valueY)
		default:
			return 0, polkavm.ErrPanicf("unexpected opcode %v", opcode)
		}
	case polkavm.InstrRegReg:
		if codeLength < i.instructionCounter+1 {
			return 0, polkavm.ErrPanicf("out of bound code access")
		}

		// let rD = min(12, (ζı+1) mod 16) , ωD ≡ ωrD , ω′D ≡ ω′rD
		regDst := polkavm.Reg(min(12, i.code[i.instructionCounter+1]%16))

		// let rA = min(12, ⌊ ζı+1 / 16 ⌋) , ωA ≡ ωrA , ω′A ≡ ω′rA
		regA := polkavm.Reg(min(12, i.code[i.instructionCounter+1]/16))

		switch opcode {
		case polkavm.MoveReg:
			i.MoveReg(regDst, regA)
		case polkavm.Sbrk:
			return 0, i.Sbrk(regDst, regA)
		case polkavm.CountSetBits64:
			i.CountSetBits64(regDst, regA)
		case polkavm.CountSetBits32:
			i.CountSetBits32(regDst, regA)
		case polkavm.LeadingZeroBits64:
			i.LeadingZeroBits64(regDst, regA)
		case polkavm.LeadingZeroBits32:
			i.LeadingZeroBits32(regDst, regA)
		case polkavm.TrailingZeroBits64:
			i.TrailingZeroBits64(regDst, regA)
		case polkavm.TrailingZeroBits32:
			i.TrailingZeroBits32(regDst, regA)
		case polkavm.SignExtend8:
			i.SignExtend8(regDst, regA)
		case polkavm.SignExtend16:
			i.SignExtend16(regDst, regA)
		case polkavm.ZeroExtend16:
			i.ZeroExtend16(regDst, regA)
		case polkavm.ReverseBytes:
			i.ReverseBytes(regDst, regA)
		default:
			return 0, polkavm.ErrPanicf("unexpected opcode %v", opcode)
		}
	case polkavm.InstrReg2Imm:
		// let lX = min(4, max(0, ℓ − 1))
		lenX := min(4, max(0, skip-1))
		if codeLength < i.instructionCounter+2+lenX {
			return 0, polkavm.ErrPanicf("out of bound code access")
		}
		// let rA = min(12, (ζı+1) mod 16), ωA ≡ ωrA, ω′A ≡ ω′rA
		regA := polkavm.Reg(min(12, i.code[i.instructionCounter+1]%16))
		// let rB = min(12, ⌊ ζı+1 / 16 ⌋), ωB ≡ ωrB, ω′B ≡ ω′rB
		regB := polkavm.Reg(min(12, i.code[i.instructionCounter+1]/16))

		// νX ≡ X_lX(E−1lX(ζı+2...+lX))
		valueX := uint32(0)
		if err := jam.Unmarshal(i.code[i.instructionCounter+2:i.instructionCounter+2+lenX], &valueX); err != nil {
			return 0, err
		}
		valueX = sext(valueX, lenX)

		switch opcode {
		case polkavm.StoreIndirectU8:
			return 0, i.StoreIndirectU8(regA, regB, valueX)
		case polkavm.StoreIndirectU16:
			return 0, i.StoreIndirectU16(regA, regB, valueX)
		case polkavm.StoreIndirectU32:
			return 0, i.StoreIndirectU32(regA, regB, valueX)
		case polkavm.StoreIndirectU64:
			return 0, i.StoreIndirectU64(regA, regB, valueX)
		case polkavm.LoadIndirectU8:
			return 0, i.LoadIndirectU8(regA, regB, valueX)
		case polkavm.LoadIndirectI8:
			return 0, i.LoadIndirectI8(regA, regB, valueX)
		case polkavm.LoadIndirectU16:
			return 0, i.LoadIndirectU16(regA, regB, valueX)
		case polkavm.LoadIndirectI16:
			return 0, i.LoadIndirectI16(regA, regB, valueX)
		case polkavm.LoadIndirectU32:
			return 0, i.LoadIndirectU32(regA, regB, valueX)
		case polkavm.LoadIndirectI32:
			return 0, i.LoadIndirectI32(regA, regB, valueX)
		case polkavm.LoadIndirectU64:
			return 0, i.LoadIndirectU64(regA, regB, valueX)
		case polkavm.AddImm32:
			i.AddImm32(regA, regB, valueX)
		case polkavm.AndImm:
			i.AndImm(regA, regB, valueX)
		case polkavm.XorImm:
			i.XorImm(regA, regB, valueX)
		case polkavm.OrImm:
			i.OrImm(regA, regB, valueX)
		case polkavm.MulImm32:
			i.MulImm32(regA, regB, valueX)
		case polkavm.SetLessThanUnsignedImm:
			i.SetLessThanUnsignedImm(regA, regB, valueX)
		case polkavm.SetLessThanSignedImm:
			i.SetLessThanSignedImm(regA, regB, valueX)
		case polkavm.ShiftLogicalLeftImm32:
			i.ShiftLogicalLeftImm32(regA, regB, valueX)
		case polkavm.ShiftLogicalRightImm32:
			i.ShiftLogicalRightImm32(regA, regB, valueX)
		case polkavm.ShiftArithmeticRightImm32:
			i.ShiftArithmeticRightImm32(regA, regB, valueX)
		case polkavm.NegateAndAddImm32:
			i.NegateAndAddImm32(regA, regB, valueX)
		case polkavm.SetGreaterThanUnsignedImm:
			i.SetGreaterThanUnsignedImm(regA, regB, valueX)
		case polkavm.SetGreaterThanSignedImm:
			i.SetGreaterThanSignedImm(regA, regB, valueX)
		case polkavm.ShiftLogicalRightImmAlt32:
			i.ShiftLogicalRightImmAlt32(regA, regB, valueX)
		case polkavm.ShiftArithmeticRightImmAlt32:
			i.ShiftArithmeticRightImmAlt32(regA, regB, valueX)
		case polkavm.ShiftLogicalLeftImmAlt32:
			i.ShiftLogicalLeftImmAlt32(regA, regB, valueX)
		case polkavm.CmovIfZeroImm:
			i.CmovIfZeroImm(regA, regB, valueX)
		case polkavm.CmovIfNotZeroImm:
			i.CmovIfNotZeroImm(regA, regB, valueX)
		case polkavm.AddImm64:
			i.AddImm64(regA, regB, valueX)
		case polkavm.MulImm64:
			i.MulImm64(regA, regB, valueX)
		case polkavm.ShiftLogicalLeftImm64:
			i.ShiftLogicalLeftImm64(regA, regB, valueX)
		case polkavm.ShiftLogicalRightImm64:
			i.ShiftLogicalRightImm64(regA, regB, valueX)
		case polkavm.ShiftArithmeticRightImm64:
			i.ShiftArithmeticRightImm64(regA, regB, valueX)
		case polkavm.NegateAndAddImm64:
			i.NegateAndAddImm64(regA, regB, valueX)
		case polkavm.ShiftLogicalLeftImmAlt64:
			i.ShiftLogicalLeftImmAlt64(regA, regB, valueX)
		case polkavm.ShiftLogicalRightImmAlt64:
			i.ShiftLogicalRightImmAlt64(regA, regB, valueX)
		case polkavm.ShiftArithmeticRightImmAlt64:
			i.ShiftArithmeticRightImmAlt64(regA, regB, valueX)
		case polkavm.RotR64Imm:
			i.RotateRight64Imm(regA, regB, valueX)
		case polkavm.RotR64ImmAlt:
			i.RotateRight64ImmAlt(regA, regB, valueX)
		case polkavm.RotR32Imm:
			i.RotateRight32Imm(regA, regB, valueX)
		case polkavm.RotR32ImmAlt:
			i.RotateRight32ImmAlt(regA, regB, valueX)
		default:
			return 0, polkavm.ErrPanicf("unexpected opcode %v", opcode)
		}
	case polkavm.InstrReg2Offset:
		// let lX = min(4, max(0, ℓ − 1))
		lenX := min(4, max(0, skip-1))
		if codeLength < i.instructionCounter+2+lenX {
			return 0, polkavm.ErrPanicf("out of bound code access")
		}
		// let rA = min(12, (ζı+1) mod 16), ωA ≡ ωrA, ω′A ≡ ω′rA
		regA := polkavm.Reg(min(12, i.code[i.instructionCounter+1]%16))
		// let rB = min(12, ⌊ ζı+1 / 16 ⌋), ωB ≡ ωrB, ω′B ≡ ω′rB
		regB := polkavm.Reg(min(12, i.code[i.instructionCounter+1]/16))

		// νX ≡ ı + Z_lX(E−1lX(ζı+2...+lX))
		valueX := uint32(0)
		if err := jam.Unmarshal(i.code[i.instructionCounter+2:i.instructionCounter+2+lenX], &valueX); err != nil {
			return 0, err
		}
		valueX = i.instructionCounter + sext(valueX, lenX)

		switch opcode {
		case polkavm.BranchEq:
			return 0, i.BranchEq(regA, regB, valueX)
		case polkavm.BranchNotEq:
			return 0, i.BranchNotEq(regA, regB, valueX)
		case polkavm.BranchLessUnsigned:
			return 0, i.BranchLessUnsigned(regA, regB, valueX)
		case polkavm.BranchLessSigned:
			return 0, i.BranchLessSigned(regA, regB, valueX)
		case polkavm.BranchGreaterOrEqualUnsigned:
			return 0, i.BranchGreaterOrEqualUnsigned(regA, regB, valueX)
		case polkavm.BranchGreaterOrEqualSigned:
			return 0, i.BranchGreaterOrEqualSigned(regA, regB, valueX)
		default:
			return 0, polkavm.ErrPanicf("unexpected opcode %v", opcode)
		}
	case polkavm.InstrReg2Imm2:
		if codeLength < i.instructionCounter+3 {
			return 0, polkavm.ErrPanicf("out of bound code access")
		}
		// let rA = min(12, (ζı+1) mod 16), ωA ≡ ωrA, ω′A ≡ ω′rA
		regA := polkavm.Reg(min(12, i.code[i.instructionCounter+1]%16))
		// let rB = min(12, ⌊ ζı+1 / 16 ⌋), ωB ≡ ωrB, ω′B ≡ ω′rB
		regB := polkavm.Reg(min(12, i.code[i.instructionCounter+1]/16))
		// let lX = min(4, ζı+2 mod 8)
		lenX := uint32(min(4, i.code[i.instructionCounter+2]%8))
		// let lY = min(4, max(0, ℓ − lX − 2))
		lenY := min(4, max(0, skip-lenX-2))

		if codeLength < i.instructionCounter+3+lenX+lenY {
			return 0, polkavm.ErrPanicf("out of bound code access")
		}

		// νX = X_lX (E−1lX (ζı+3⋅⋅⋅+lX))
		valueX := uint32(0)
		if err := jam.Unmarshal(i.code[i.instructionCounter+3:i.instructionCounter+3+lenX], &valueX); err != nil {
			return 0, err
		}
		// vY = X_lY (E−1lY (ζı+3+lX ⋅⋅⋅+lY))
		valueY := uint32(0)
		if err := jam.Unmarshal(i.code[i.instructionCounter+3+lenX:i.instructionCounter+3+lenX+lenY], &valueY); err != nil {
			return 0, err
		}
		valueY = sext(valueY, lenY)

		switch opcode {
		case polkavm.LoadImmAndJumpIndirect:
			return 0, i.LoadImmAndJumpIndirect(regA, regB, valueX, valueY)
		default:
			return 0, polkavm.ErrPanicf("unexpected opcode %v", opcode)
		}
	case polkavm.InstrReg3:
		if codeLength < i.instructionCounter+2 {
			return 0, polkavm.ErrPanicf("out of bound code access")
		}

		// let rA = min(12, (ζı+1) mod 16), ωA ≡ ωrA, ω′A ≡ ω′rA
		regA := polkavm.Reg(min(12, i.code[i.instructionCounter+1]%16))
		// let rB = min(12, ⌊ ζı+1 / 16 ⌋), ωB ≡ ωrB, ω′B ≡ ω′rB
		regB := polkavm.Reg(min(12, i.code[i.instructionCounter+1]/16))
		// let rD = min(12, ζı+2), ωD ≡ ωrD, ω′D ≡ ω′rD
		regDst := polkavm.Reg(min(12, i.code[i.instructionCounter+2]))

		switch opcode {
		case polkavm.Add32:
			i.Add32(regDst, regA, regB)
		case polkavm.Sub32:
			i.Sub32(regDst, regA, regB)
		case polkavm.Mul32:
			i.Mul32(regDst, regA, regB)
		case polkavm.DivUnsigned32:
			i.DivUnsigned32(regDst, regA, regB)
		case polkavm.DivSigned32:
			i.DivSigned32(regDst, regA, regB)
		case polkavm.RemUnsigned32:
			i.RemUnsigned32(regDst, regA, regB)
		case polkavm.RemSigned32:
			i.RemSigned32(regDst, regA, regB)
		case polkavm.ShiftLogicalLeft32:
			i.ShiftLogicalLeft32(regDst, regA, regB)
		case polkavm.ShiftLogicalRight32:
			i.ShiftLogicalRight32(regDst, regA, regB)
		case polkavm.ShiftArithmeticRight32:
			i.ShiftArithmeticRight32(regDst, regA, regB)
		case polkavm.Add64:
			i.Add64(regDst, regA, regB)
		case polkavm.Sub64:
			i.Sub64(regDst, regA, regB)
		case polkavm.Mul64:
			i.Mul64(regDst, regA, regB)
		case polkavm.DivUnsigned64:
			i.DivUnsigned64(regDst, regA, regB)
		case polkavm.DivSigned64:
			i.DivSigned64(regDst, regA, regB)
		case polkavm.RemUnsigned64:
			i.RemUnsigned64(regDst, regA, regB)
		case polkavm.RemSigned64:
			i.RemSigned64(regDst, regA, regB)
		case polkavm.ShiftLogicalLeft64:
			i.ShiftLogicalLeft64(regDst, regA, regB)
		case polkavm.ShiftLogicalRight64:
			i.ShiftLogicalRight64(regDst, regA, regB)
		case polkavm.ShiftArithmeticRight64:
			i.ShiftArithmeticRight64(regDst, regA, regB)
		case polkavm.And:
			i.And(regDst, regA, regB)
		case polkavm.Xor:
			i.Xor(regDst, regA, regB)
		case polkavm.Or:
			i.Or(regDst, regA, regB)
		case polkavm.MulUpperSignedSigned:
			i.MulUpperSignedSigned(regDst, regA, regB)
		case polkavm.MulUpperUnsignedUnsigned:
			i.MulUpperUnsignedUnsigned(regDst, regA, regB)
		case polkavm.MulUpperSignedUnsigned:
			i.MulUpperSignedUnsigned(regDst, regA, regB)
		case polkavm.SetLessThanUnsigned:
			i.SetLessThanUnsigned(regDst, regA, regB)
		case polkavm.SetLessThanSigned:
			i.SetLessThanSigned(regDst, regA, regB)
		case polkavm.CmovIfZero:
			i.CmovIfZero(regDst, regA, regB)
		case polkavm.CmovIfNotZero:
			i.CmovIfNotZero(regDst, regA, regB)
		case polkavm.RotL64:
			i.RotateLeft64(regDst, regA, regB)
		case polkavm.RotL32:
			i.RotateLeft32(regDst, regA, regB)
		case polkavm.RotR64:
			i.RotateRight64(regDst, regA, regB)
		case polkavm.RotR32:
			i.RotateRight32(regDst, regA, regB)
		case polkavm.AndInv:
			i.AndInverted(regDst, regA, regB)
		case polkavm.OrInv:
			i.OrInverted(regDst, regA, regB)
		case polkavm.Xnor:
			i.Xnor(regDst, regA, regB)
		case polkavm.Max:
			i.Max(regDst, regA, regB)
		case polkavm.MaxU:
			i.MaxUnsigned(regDst, regA, regB)
		case polkavm.Min:
			i.Min(regDst, regA, regB)
		case polkavm.MinU:
			i.MinUnsigned(regDst, regA, regB)
		default:
			return 0, polkavm.ErrPanicf("unexpected opcode %v", opcode)
		}
	}
	return 0, nil
}

// Xn∈{0,1,2,3,4,8}∶ N^28n → N_R
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
