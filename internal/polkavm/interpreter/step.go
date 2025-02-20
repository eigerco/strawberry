package interpreter

import (
	"github.com/eigerco/strawberry/internal/polkavm"
	"github.com/eigerco/strawberry/pkg/serialization/codec/jam"
)

// step Ψ1(Y, B, ⟦NR⟧, NR, NG, ⟦NR⟧13, M) → ({☇, ∎, ▸} ∪ {F ,̵ h} × NR, NR, ZG, _⟦NR⟧13, M)
func (i *Instance) step() (uint64, error) {
	codeLength := uint64(len(i.code))
	// ℓ ≡ skip(ı) (eq. A.18)
	skip := polkavm.Skip(i.instructionCounter, i.bitmask)

	// ζ_ı
	opcode := polkavm.Opcode(i.code[i.instructionCounter])

	if err := i.deductGas(polkavm.GasCosts[opcode]); err != nil {
		return 0, err
	}

	// wrap mutator with logging
	var m polkavm.Mutator = i
	if i.log != nil {
		m = NewLogger(i, i.log)
	}

	switch polkavm.InstructionForType[opcode] {
	case polkavm.InstrNone:
		switch opcode {
		case polkavm.Trap:
			return 0, m.Trap()
		case polkavm.Fallthrough:
			m.Fallthrough()
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
		var valueX uint64
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
			m.LoadImm64(polkavm.Reg(regA), valueX)
		default:
			return 0, polkavm.ErrPanicf("unexpected opcode %v", opcode)
		}
	case polkavm.InstrImm2:
		if codeLength < i.instructionCounter+2 {
			return 0, polkavm.ErrPanicf("out of bound code access")
		}
		// let lX = min(4, ζı+1 mod 8)
		lenX := uint64(min(4, i.code[i.instructionCounter+1]%8))

		// let lY = min(4, max(0, ℓ − lX − 1))
		lenY := uint64(min(4, max(0, int(skip)-int(lenX)-1)))

		if codeLength < i.instructionCounter+2+lenX+lenY {
			return 0, polkavm.ErrPanicf("out of bound code access")
		}

		// νX ≡ X_lX (E−1lX (ζı+2⋅⋅⋅+lX))
		valueX := uint64(0)
		if err := jam.Unmarshal(i.code[i.instructionCounter+2:i.instructionCounter+2+lenX], &valueX); err != nil {
			return 0, err
		}
		valueX = sext(valueX, lenX)

		// νY ≡ XlY (E−1lY (ζı+2+lX ⋅⋅⋅+lY))
		valueY := uint64(0)
		if err := jam.Unmarshal(i.code[i.instructionCounter+2+lenX:i.instructionCounter+2+lenX+lenY], &valueY); err != nil {
			return 0, err
		}
		valueY = sext(valueY, lenY)
		switch opcode {
		case polkavm.StoreImmU8:
			return 0, m.StoreImmU8(valueX, valueY)
		case polkavm.StoreImmU16:
			return 0, m.StoreImmU16(valueX, valueY)
		case polkavm.StoreImmU32:
			return 0, m.StoreImmU32(valueX, valueY)
		case polkavm.StoreImmU64:
			return 0, m.StoreImmU64(valueX, valueY)
		default:
			return 0, polkavm.ErrPanicf("unexpected opcode %v", opcode)
		}
	case polkavm.InstrOffset:
		// let lX = min(4, ℓ)
		lenX := min(4, skip)
		if codeLength < i.instructionCounter+1+lenX {
			return 0, polkavm.ErrPanicf("out of bound code access")
		}

		// νX ≡ ı + Z_lX (E−1_lX(ζı+1⋅⋅⋅+lX))
		valueX := uint64(0)
		if err := jam.Unmarshal(i.code[i.instructionCounter+1:i.instructionCounter+1+lenX], &valueX); err != nil {
			return 0, err
		}
		valueX = i.instructionCounter + sext(valueX, lenX)

		switch opcode {
		case polkavm.Jump:
			return 0, m.Jump(valueX)
		default:
			return 0, polkavm.ErrPanicf("unexpected opcode %v", opcode)
		}
	case polkavm.InstrRegImm:
		// let lX = min(4, max(0, ℓ − 1))
		lenX := uint64(min(4, max(0, int(skip)-1)))
		if codeLength < i.instructionCounter+2+lenX {
			return 0, polkavm.ErrPanicf("out of bound code access")
		}
		// let rA = min(12, ζı+1 mod 16), ω′A ≡ ω′rA
		regA := polkavm.Reg(min(12, i.code[i.instructionCounter+1]%16))

		// νX ≡ X_lX(E−1_lX(ζı+2...+lX))
		valueX := uint64(0)
		if err := jam.Unmarshal(i.code[i.instructionCounter+2:i.instructionCounter+2+lenX], &valueX); err != nil {
			return 0, err
		}
		valueX = sext(valueX, lenX)

		switch opcode {
		case polkavm.JumpIndirect:
			return 0, m.JumpIndirect(regA, valueX)
		case polkavm.LoadImm:
			m.LoadImm(regA, valueX)
		case polkavm.LoadU8:
			return 0, m.LoadU8(regA, valueX)
		case polkavm.LoadI8:
			return 0, m.LoadI8(regA, valueX)
		case polkavm.LoadU16:
			return 0, m.LoadU16(regA, valueX)
		case polkavm.LoadI16:
			return 0, m.LoadI16(regA, valueX)
		case polkavm.LoadU32:
			return 0, m.LoadU32(regA, valueX)
		case polkavm.LoadI32:
			return 0, m.LoadI32(regA, valueX)
		case polkavm.LoadU64:
			return 0, m.LoadU64(regA, valueX)
		case polkavm.StoreU8:
			return 0, m.StoreU8(regA, valueX)
		case polkavm.StoreU16:
			return 0, m.StoreU16(regA, valueX)
		case polkavm.StoreU32:
			return 0, m.StoreU32(regA, valueX)
		case polkavm.StoreU64:
			return 0, m.StoreU64(regA, valueX)
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
		lenX := uint64(min(4, (i.code[i.instructionCounter+1]/16)%8))

		// let lY = min(4, max(0, ℓ − lX − 1))
		lenY := uint64(min(4, max(0, int(skip)-int(lenX)-1)))

		if codeLength < i.instructionCounter+2+lenX+lenY {
			return 0, polkavm.ErrPanicf("out of bound code access")
		}

		// νX = X_lX (E−1lX (ζı+2⋅⋅⋅+lX))
		valueX := uint64(0)
		if err := jam.Unmarshal(i.code[i.instructionCounter+2:i.instructionCounter+2+lenX], &valueX); err != nil {
			return 0, err
		}
		valueX = sext(valueX, lenX)

		// νY = ı + Z_lY (E−1lY (ζı+2+lX ⋅⋅⋅+lY))
		valueY := uint64(0)
		if err := jam.Unmarshal(i.code[i.instructionCounter+2+lenX:i.instructionCounter+2+lenX+lenY], &valueY); err != nil {
			return 0, err
		}
		valueY = sext(valueY, lenY)

		switch opcode {
		case polkavm.StoreImmIndirectU8:
			return 0, m.StoreImmIndirectU8(regA, valueX, valueY)
		case polkavm.StoreImmIndirectU16:
			return 0, m.StoreImmIndirectU16(regA, valueX, valueY)
		case polkavm.StoreImmIndirectU32:
			return 0, m.StoreImmIndirectU32(regA, valueX, valueY)
		case polkavm.StoreImmIndirectU64:
			return 0, m.StoreImmIndirectU64(regA, valueX, valueY)
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
		lenX := uint64(min(4, (i.code[i.instructionCounter+1]/16)%8))
		// let lY = min(4, max(0, ℓ − lX − 1))
		lenY := uint64(min(4, max(0, int(skip)-int(lenX)-1)))

		if codeLength < i.instructionCounter+2+lenX+lenY {
			return 0, polkavm.ErrPanicf("out of bound code access")
		}

		// νX = X_lX(E−1lX (ζı+2...+lX))
		valueX := uint64(0)
		if err := jam.Unmarshal(i.code[i.instructionCounter+2:i.instructionCounter+2+lenX], &valueX); err != nil {
			return 0, err
		}
		valueX = sext(valueX, lenX)
		// vY = X_lY(E−1lY (ζı+2+lX...+lY))
		valueY := uint64(0)
		if err := jam.Unmarshal(i.code[i.instructionCounter+2+lenX:i.instructionCounter+2+lenX+lenY], &valueY); err != nil {
			return 0, err
		}
		valueY = i.instructionCounter + sext(valueY, lenY)

		switch opcode {
		case polkavm.LoadImmAndJump:
			return 0, m.LoadImmAndJump(regA, valueX, valueY)
		case polkavm.BranchEqImm:
			return 0, m.BranchEqImm(regA, valueX, valueY)
		case polkavm.BranchNotEqImm:
			return 0, m.BranchNotEqImm(regA, valueX, valueY)
		case polkavm.BranchLessUnsignedImm:
			return 0, m.BranchLessUnsignedImm(regA, valueX, valueY)
		case polkavm.BranchLessOrEqualUnsignedImm:
			return 0, m.BranchLessOrEqualUnsignedImm(regA, valueX, valueY)
		case polkavm.BranchGreaterOrEqualUnsignedImm:
			return 0, m.BranchGreaterOrEqualUnsignedImm(regA, valueX, valueY)
		case polkavm.BranchGreaterUnsignedImm:
			return 0, m.BranchGreaterUnsignedImm(regA, valueX, valueY)
		case polkavm.BranchLessSignedImm:
			return 0, m.BranchLessSignedImm(regA, valueX, valueY)
		case polkavm.BranchLessOrEqualSignedImm:
			return 0, m.BranchLessOrEqualSignedImm(regA, valueX, valueY)
		case polkavm.BranchGreaterOrEqualSignedImm:
			return 0, m.BranchGreaterOrEqualSignedImm(regA, valueX, valueY)
		case polkavm.BranchGreaterSignedImm:
			return 0, m.BranchGreaterSignedImm(regA, valueX, valueY)
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
			m.MoveReg(regDst, regA)
		case polkavm.Sbrk:
			return 0, m.Sbrk(regDst, regA)
		case polkavm.CountSetBits64:
			m.CountSetBits64(regDst, regA)
		case polkavm.CountSetBits32:
			m.CountSetBits32(regDst, regA)
		case polkavm.LeadingZeroBits64:
			m.LeadingZeroBits64(regDst, regA)
		case polkavm.LeadingZeroBits32:
			m.LeadingZeroBits32(regDst, regA)
		case polkavm.TrailingZeroBits64:
			m.TrailingZeroBits64(regDst, regA)
		case polkavm.TrailingZeroBits32:
			m.TrailingZeroBits32(regDst, regA)
		case polkavm.SignExtend8:
			m.SignExtend8(regDst, regA)
		case polkavm.SignExtend16:
			m.SignExtend16(regDst, regA)
		case polkavm.ZeroExtend16:
			m.ZeroExtend16(regDst, regA)
		case polkavm.ReverseBytes:
			m.ReverseBytes(regDst, regA)
		default:
			return 0, polkavm.ErrPanicf("unexpected opcode %v", opcode)
		}
	case polkavm.InstrReg2Imm:
		// let lX = min(4, max(0, ℓ − 1))
		lenX := uint64(min(4, max(0, int(skip)-1)))
		if codeLength < i.instructionCounter+2+lenX {
			return 0, polkavm.ErrPanicf("out of bound code access")
		}
		// let rA = min(12, (ζı+1) mod 16), ωA ≡ ωrA, ω′A ≡ ω′rA
		regA := polkavm.Reg(min(12, i.code[i.instructionCounter+1]%16))
		// let rB = min(12, ⌊ ζı+1 / 16 ⌋), ωB ≡ ωrB, ω′B ≡ ω′rB
		regB := polkavm.Reg(min(12, i.code[i.instructionCounter+1]/16))

		// νX ≡ X_lX(E−1lX(ζı+2...+lX))
		valueX := uint64(0)
		if err := jam.Unmarshal(i.code[i.instructionCounter+2:i.instructionCounter+2+lenX], &valueX); err != nil {
			return 0, err
		}
		valueX = sext(valueX, lenX)

		switch opcode {
		case polkavm.StoreIndirectU8:
			return 0, m.StoreIndirectU8(regA, regB, valueX)
		case polkavm.StoreIndirectU16:
			return 0, m.StoreIndirectU16(regA, regB, valueX)
		case polkavm.StoreIndirectU32:
			return 0, m.StoreIndirectU32(regA, regB, valueX)
		case polkavm.StoreIndirectU64:
			return 0, m.StoreIndirectU64(regA, regB, valueX)
		case polkavm.LoadIndirectU8:
			return 0, m.LoadIndirectU8(regA, regB, valueX)
		case polkavm.LoadIndirectI8:
			return 0, m.LoadIndirectI8(regA, regB, valueX)
		case polkavm.LoadIndirectU16:
			return 0, m.LoadIndirectU16(regA, regB, valueX)
		case polkavm.LoadIndirectI16:
			return 0, m.LoadIndirectI16(regA, regB, valueX)
		case polkavm.LoadIndirectU32:
			return 0, m.LoadIndirectU32(regA, regB, valueX)
		case polkavm.LoadIndirectI32:
			return 0, m.LoadIndirectI32(regA, regB, valueX)
		case polkavm.LoadIndirectU64:
			return 0, m.LoadIndirectU64(regA, regB, valueX)
		case polkavm.AddImm32:
			m.AddImm32(regA, regB, valueX)
		case polkavm.AndImm:
			m.AndImm(regA, regB, valueX)
		case polkavm.XorImm:
			m.XorImm(regA, regB, valueX)
		case polkavm.OrImm:
			m.OrImm(regA, regB, valueX)
		case polkavm.MulImm32:
			m.MulImm32(regA, regB, valueX)
		case polkavm.SetLessThanUnsignedImm:
			m.SetLessThanUnsignedImm(regA, regB, valueX)
		case polkavm.SetLessThanSignedImm:
			m.SetLessThanSignedImm(regA, regB, valueX)
		case polkavm.ShiftLogicalLeftImm32:
			m.ShiftLogicalLeftImm32(regA, regB, valueX)
		case polkavm.ShiftLogicalRightImm32:
			m.ShiftLogicalRightImm32(regA, regB, valueX)
		case polkavm.ShiftArithmeticRightImm32:
			m.ShiftArithmeticRightImm32(regA, regB, valueX)
		case polkavm.NegateAndAddImm32:
			m.NegateAndAddImm32(regA, regB, valueX)
		case polkavm.SetGreaterThanUnsignedImm:
			m.SetGreaterThanUnsignedImm(regA, regB, valueX)
		case polkavm.SetGreaterThanSignedImm:
			m.SetGreaterThanSignedImm(regA, regB, valueX)
		case polkavm.ShiftLogicalLeftImmAlt32:
			m.ShiftLogicalLeftImmAlt32(regA, regB, valueX)
		case polkavm.ShiftArithmeticRightImmAlt32:
			m.ShiftLogicalRightImmAlt32(regA, regB, valueX)
		case polkavm.ShiftLogicalRightImmAlt32:
			m.ShiftArithmeticRightImmAlt32(regA, regB, valueX)
		case polkavm.CmovIfZeroImm:
			m.CmovIfZeroImm(regA, regB, valueX)
		case polkavm.CmovIfNotZeroImm:
			m.CmovIfNotZeroImm(regA, regB, valueX)
		case polkavm.AddImm64:
			m.AddImm64(regA, regB, valueX)
		case polkavm.MulImm64:
			m.MulImm64(regA, regB, valueX)
		case polkavm.ShiftLogicalLeftImm64:
			m.ShiftLogicalLeftImm64(regA, regB, valueX)
		case polkavm.ShiftLogicalRightImm64:
			m.ShiftLogicalRightImm64(regA, regB, valueX)
		case polkavm.ShiftArithmeticRightImm64:
			m.ShiftArithmeticRightImm64(regA, regB, valueX)
		case polkavm.NegateAndAddImm64:
			m.NegateAndAddImm64(regA, regB, valueX)
		case polkavm.ShiftLogicalLeftImmAlt64:
			m.ShiftLogicalLeftImmAlt64(regA, regB, valueX)
		case polkavm.ShiftLogicalRightImmAlt64:
			m.ShiftLogicalRightImmAlt64(regA, regB, valueX)
		case polkavm.ShiftArithmeticRightImmAlt64:
			m.ShiftArithmeticRightImmAlt64(regA, regB, valueX)
		case polkavm.RotR64Imm:
			m.RotateRight64Imm(regA, regB, valueX)
		case polkavm.RotR64ImmAlt:
			m.RotateRight64ImmAlt(regA, regB, valueX)
		case polkavm.RotR32Imm:
			m.RotateRight32Imm(regA, regB, valueX)
		case polkavm.RotR32ImmAlt:
			m.RotateRight32ImmAlt(regA, regB, valueX)
		default:
			return 0, polkavm.ErrPanicf("unexpected opcode %v", opcode)
		}
	case polkavm.InstrReg2Offset:
		// let lX = min(4, max(0, ℓ − 1))
		lenX := uint64(min(4, max(0, int(skip)-1)))
		if codeLength < i.instructionCounter+2+lenX {
			return 0, polkavm.ErrPanicf("out of bound code access")
		}
		// let rA = min(12, (ζı+1) mod 16), ωA ≡ ωrA, ω′A ≡ ω′rA
		regA := polkavm.Reg(min(12, i.code[i.instructionCounter+1]%16))
		// let rB = min(12, ⌊ ζı+1 / 16 ⌋), ωB ≡ ωrB, ω′B ≡ ω′rB
		regB := polkavm.Reg(min(12, i.code[i.instructionCounter+1]/16))

		// νX ≡ ı + Z_lX(E−1lX(ζı+2...+lX))
		valueX := uint64(0)
		if err := jam.Unmarshal(i.code[i.instructionCounter+2:i.instructionCounter+2+lenX], &valueX); err != nil {
			return 0, err
		}
		valueX = i.instructionCounter + sext(valueX, lenX)

		switch opcode {
		case polkavm.BranchEq:
			return 0, m.BranchEq(regA, regB, valueX)
		case polkavm.BranchNotEq:
			return 0, m.BranchNotEq(regA, regB, valueX)
		case polkavm.BranchLessUnsigned:
			return 0, m.BranchLessUnsigned(regA, regB, valueX)
		case polkavm.BranchLessSigned:
			return 0, m.BranchLessSigned(regA, regB, valueX)
		case polkavm.BranchGreaterOrEqualUnsigned:
			return 0, m.BranchGreaterOrEqualUnsigned(regA, regB, valueX)
		case polkavm.BranchGreaterOrEqualSigned:
			return 0, m.BranchGreaterOrEqualSigned(regA, regB, valueX)
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
		lenX := uint64(min(4, i.code[i.instructionCounter+2]%8))
		// let lY = min(4, max(0, ℓ − lX − 2))
		lenY := uint64(min(4, max(0, int(skip)-int(lenX)-2)))

		if codeLength < i.instructionCounter+3+lenX+lenY {
			return 0, polkavm.ErrPanicf("out of bound code access")
		}

		// νX = X_lX(E−1lX (ζı+3⋅⋅⋅+lX))
		valueX := uint64(0)
		if err := jam.Unmarshal(i.code[i.instructionCounter+3:i.instructionCounter+3+lenX], &valueX); err != nil {
			return 0, err
		}
		// vY = X_lY(E−1lY (ζı+3+lX ⋅⋅⋅+lY))
		valueY := uint64(0)
		if err := jam.Unmarshal(i.code[i.instructionCounter+3+lenX:i.instructionCounter+3+lenX+lenY], &valueY); err != nil {
			return 0, err
		}
		valueY = sext(valueY, lenY)

		switch opcode {
		case polkavm.LoadImmAndJumpIndirect:
			return 0, m.LoadImmAndJumpIndirect(regA, regB, valueX, valueY)
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
			m.Add32(regDst, regA, regB)
		case polkavm.Sub32:
			m.Sub32(regDst, regA, regB)
		case polkavm.Mul32:
			m.Mul32(regDst, regA, regB)
		case polkavm.DivUnsigned32:
			m.DivUnsigned32(regDst, regA, regB)
		case polkavm.DivSigned32:
			m.DivSigned32(regDst, regA, regB)
		case polkavm.RemUnsigned32:
			m.RemUnsigned32(regDst, regA, regB)
		case polkavm.RemSigned32:
			m.RemSigned32(regDst, regA, regB)
		case polkavm.ShiftLogicalLeft32:
			m.ShiftLogicalLeft32(regDst, regA, regB)
		case polkavm.ShiftLogicalRight32:
			m.ShiftLogicalRight32(regDst, regA, regB)
		case polkavm.ShiftArithmeticRight32:
			m.ShiftArithmeticRight32(regDst, regA, regB)
		case polkavm.Add64:
			m.Add64(regDst, regA, regB)
		case polkavm.Sub64:
			m.Sub64(regDst, regA, regB)
		case polkavm.Mul64:
			m.Mul64(regDst, regA, regB)
		case polkavm.DivUnsigned64:
			m.DivUnsigned64(regDst, regA, regB)
		case polkavm.DivSigned64:
			m.DivSigned64(regDst, regA, regB)
		case polkavm.RemUnsigned64:
			m.RemUnsigned64(regDst, regA, regB)
		case polkavm.RemSigned64:
			m.RemSigned64(regDst, regA, regB)
		case polkavm.ShiftLogicalLeft64:
			m.ShiftLogicalLeft64(regDst, regA, regB)
		case polkavm.ShiftLogicalRight64:
			m.ShiftLogicalRight64(regDst, regA, regB)
		case polkavm.ShiftArithmeticRight64:
			m.ShiftArithmeticRight64(regDst, regA, regB)
		case polkavm.And:
			m.And(regDst, regA, regB)
		case polkavm.Xor:
			m.Xor(regDst, regA, regB)
		case polkavm.Or:
			m.Or(regDst, regA, regB)
		case polkavm.MulUpperSignedSigned:
			m.MulUpperSignedSigned(regDst, regA, regB)
		case polkavm.MulUpperUnsignedUnsigned:
			m.MulUpperUnsignedUnsigned(regDst, regA, regB)
		case polkavm.MulUpperSignedUnsigned:
			m.MulUpperSignedUnsigned(regDst, regA, regB)
		case polkavm.SetLessThanUnsigned:
			m.SetLessThanUnsigned(regDst, regA, regB)
		case polkavm.SetLessThanSigned:
			m.SetLessThanSigned(regDst, regA, regB)
		case polkavm.CmovIfZero:
			m.CmovIfZero(regDst, regA, regB)
		case polkavm.CmovIfNotZero:
			m.CmovIfNotZero(regDst, regA, regB)
		case polkavm.RotL64:
			m.RotateLeft64(regDst, regA, regB)
		case polkavm.RotL32:
			m.RotateLeft32(regDst, regA, regB)
		case polkavm.RotR64:
			m.RotateRight64(regDst, regA, regB)
		case polkavm.RotR32:
			m.RotateRight32(regDst, regA, regB)
		case polkavm.AndInv:
			m.AndInverted(regDst, regA, regB)
		case polkavm.OrInv:
			m.OrInverted(regDst, regA, regB)
		case polkavm.Xnor:
			m.Xnor(regDst, regA, regB)
		case polkavm.Max:
			m.Max(regDst, regA, regB)
		case polkavm.MaxU:
			m.MaxUnsigned(regDst, regA, regB)
		case polkavm.Min:
			m.Min(regDst, regA, regB)
		case polkavm.MinU:
			m.MinUnsigned(regDst, regA, regB)
		default:
			return 0, polkavm.ErrPanicf("unexpected opcode %v", opcode)
		}
	}
	return 0, nil
}

// Xn∈{0,1,2,3,4,8}∶ N^28n → N_R
func sext(value uint64, length uint64) uint64 {
	switch length {
	case 0:
		return 0
	case 1:
		return uint64(int64(int8(uint8(value))))
	case 2:
		return uint64(int64(int16(uint16(value))))
	case 3:
		return uint64((int32(value << 8)) >> 8)
	case 4:
		return uint64(int64(int32(value)))
	case 8:
		return uint64(int64(value))
	default:
		panic("unreachable")
	}
}
