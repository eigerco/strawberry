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
	switch opcode {
	case polkavm.Trap:
		if err := i.deductGas(polkavm.TrapCost); err != nil {
			return 0, err
		}
		return 0, i.Trap()
	case polkavm.Fallthrough:
		if err := i.deductGas(polkavm.FallthroughCost); err != nil {
			return 0, err
		}
		i.Fallthrough()

	// (eq. A.21 v0.7.0)
	case polkavm.Ecalli:
		if err := i.deductGas(polkavm.EcalliCost); err != nil {
			return 0, err
		}
		// ε = ħ × νX
		return i.decodeArgsImm(), polkavm.ErrHostCall

	// (eq. A.22 v0.7.0)
	case polkavm.LoadImm64:
		if err := i.deductGas(polkavm.LoadImm64Cost); err != nil {
			return 0, err
		}
		i.LoadImm64(i.decodeArgsRegImmExt())

	// (eq. A.23 v0.7.0)
	case polkavm.StoreImmU8:
		if err := i.deductGas(polkavm.StoreImmU8Cost); err != nil {
			return 0, err
		}
		return 0, i.StoreImmU8(i.decodeArgsImm2())
	case polkavm.StoreImmU16:
		if err := i.deductGas(polkavm.StoreImmU16Cost); err != nil {
			return 0, err
		}
		return 0, i.StoreImmU16(i.decodeArgsImm2())
	case polkavm.StoreImmU32:
		if err := i.deductGas(polkavm.StoreImmU32Cost); err != nil {
			return 0, err
		}
		return 0, i.StoreImmU32(i.decodeArgsImm2())
	case polkavm.StoreImmU64:
		if err := i.deductGas(polkavm.StoreImmU64Cost); err != nil {
			return 0, err
		}
		return 0, i.StoreImmU64(i.decodeArgsImm2())

	// (eq. A.24 v0.7.0)
	case polkavm.Jump:
		if err := i.deductGas(polkavm.JumpCost); err != nil {
			return 0, err
		}
		return 0, i.Jump(i.decodeArgsOffset())

	// (eq. A.25 v0.7.0)
	case polkavm.JumpIndirect:
		if err := i.deductGas(polkavm.JumpIndirectCost); err != nil {
			return 0, err
		}
		return 0, i.JumpIndirect(i.decodeArgsRegImm())
	case polkavm.LoadImm:
		if err := i.deductGas(polkavm.LoadImmCost); err != nil {
			return 0, err
		}
		i.LoadImm(i.decodeArgsRegImm())
	case polkavm.LoadU8:
		if err := i.deductGas(polkavm.LoadU8Cost); err != nil {
			return 0, err
		}
		return 0, i.LoadU8(i.decodeArgsRegImm())
	case polkavm.LoadI8:
		if err := i.deductGas(polkavm.LoadI8Cost); err != nil {
			return 0, err
		}
		return 0, i.LoadI8(i.decodeArgsRegImm())
	case polkavm.LoadU16:
		if err := i.deductGas(polkavm.LoadU16Cost); err != nil {
			return 0, err
		}
		return 0, i.LoadU16(i.decodeArgsRegImm())
	case polkavm.LoadI16:
		if err := i.deductGas(polkavm.LoadI16Cost); err != nil {
			return 0, err
		}
		return 0, i.LoadI16(i.decodeArgsRegImm())
	case polkavm.LoadU32:
		if err := i.deductGas(polkavm.LoadU32Cost); err != nil {
			return 0, err
		}
		return 0, i.LoadU32(i.decodeArgsRegImm())
	case polkavm.LoadI32:
		if err := i.deductGas(polkavm.LoadI32Cost); err != nil {
			return 0, err
		}
		return 0, i.LoadI32(i.decodeArgsRegImm())
	case polkavm.LoadU64:
		if err := i.deductGas(polkavm.LoadU64Cost); err != nil {
			return 0, err
		}
		return 0, i.LoadU64(i.decodeArgsRegImm())
	case polkavm.StoreU8:
		if err := i.deductGas(polkavm.StoreU8Cost); err != nil {
			return 0, err
		}
		return 0, i.StoreU8(i.decodeArgsRegImm())
	case polkavm.StoreU16:
		if err := i.deductGas(polkavm.StoreU16Cost); err != nil {
			return 0, err
		}
		return 0, i.StoreU16(i.decodeArgsRegImm())
	case polkavm.StoreU32:
		if err := i.deductGas(polkavm.StoreU32Cost); err != nil {
			return 0, err
		}
		return 0, i.StoreU32(i.decodeArgsRegImm())
	case polkavm.StoreU64:
		if err := i.deductGas(polkavm.StoreU64Cost); err != nil {
			return 0, err
		}
		return 0, i.StoreU64(i.decodeArgsRegImm())

	// (eq. A.26 v0.7.0)
	case polkavm.StoreImmIndirectU8:
		if err := i.deductGas(polkavm.StoreImmIndirectU8Cost); err != nil {
			return 0, err
		}
		return 0, i.StoreImmIndirectU8(i.decodeArgsRegImm2())
	case polkavm.StoreImmIndirectU16:
		if err := i.deductGas(polkavm.StoreImmIndirectU16Cost); err != nil {
			return 0, err
		}
		return 0, i.StoreImmIndirectU16(i.decodeArgsRegImm2())
	case polkavm.StoreImmIndirectU32:
		if err := i.deductGas(polkavm.StoreImmIndirectU32Cost); err != nil {
			return 0, err
		}
		return 0, i.StoreImmIndirectU32(i.decodeArgsRegImm2())
	case polkavm.StoreImmIndirectU64:
		if err := i.deductGas(polkavm.StoreImmIndirectU64Cost); err != nil {
			return 0, err
		}
		return 0, i.StoreImmIndirectU64(i.decodeArgsRegImm2())

	// (eq. A.27 v0.7.0)
	case polkavm.LoadImmAndJump:
		if err := i.deductGas(polkavm.LoadImmAndJumpCost); err != nil {
			return 0, err
		}
		return 0, i.LoadImmAndJump(i.decodeArgsRegImmOffset())
	case polkavm.BranchEqImm:
		if err := i.deductGas(polkavm.BranchEqImmCost); err != nil {
			return 0, err
		}
		return 0, i.BranchEqImm(i.decodeArgsRegImmOffset())
	case polkavm.BranchNotEqImm:
		if err := i.deductGas(polkavm.BranchNotEqImmCost); err != nil {
			return 0, err
		}
		return 0, i.BranchNotEqImm(i.decodeArgsRegImmOffset())
	case polkavm.BranchLessUnsignedImm:
		if err := i.deductGas(polkavm.BranchLessUnsignedImmCost); err != nil {
			return 0, err
		}
		return 0, i.BranchLessUnsignedImm(i.decodeArgsRegImmOffset())
	case polkavm.BranchLessOrEqualUnsignedImm:
		if err := i.deductGas(polkavm.BranchLessOrEqualUnsignedImmCost); err != nil {
			return 0, err
		}
		return 0, i.BranchLessOrEqualUnsignedImm(i.decodeArgsRegImmOffset())
	case polkavm.BranchGreaterOrEqualUnsignedImm:
		if err := i.deductGas(polkavm.BranchGreaterOrEqualUnsignedImmCost); err != nil {
			return 0, err
		}
		return 0, i.BranchGreaterOrEqualUnsignedImm(i.decodeArgsRegImmOffset())
	case polkavm.BranchGreaterUnsignedImm:
		if err := i.deductGas(polkavm.BranchGreaterUnsignedImmCost); err != nil {
			return 0, err
		}
		return 0, i.BranchGreaterUnsignedImm(i.decodeArgsRegImmOffset())
	case polkavm.BranchLessSignedImm:
		if err := i.deductGas(polkavm.BranchLessSignedImmCost); err != nil {
			return 0, err
		}
		return 0, i.BranchLessSignedImm(i.decodeArgsRegImmOffset())
	case polkavm.BranchLessOrEqualSignedImm:
		if err := i.deductGas(polkavm.BranchLessOrEqualSignedImmCost); err != nil {
			return 0, err
		}
		return 0, i.BranchLessOrEqualSignedImm(i.decodeArgsRegImmOffset())
	case polkavm.BranchGreaterOrEqualSignedImm:
		if err := i.deductGas(polkavm.BranchGreaterOrEqualSignedImmCost); err != nil {
			return 0, err
		}
		return 0, i.BranchGreaterOrEqualSignedImm(i.decodeArgsRegImmOffset())
	case polkavm.BranchGreaterSignedImm:
		if err := i.deductGas(polkavm.BranchGreaterSignedImmCost); err != nil {
			return 0, err
		}
		return 0, i.BranchGreaterSignedImm(i.decodeArgsRegImmOffset())

	// (eq. A.28 v0.7.0)
	case polkavm.MoveReg:
		if err := i.deductGas(polkavm.MoveRegCost); err != nil {
			return 0, err
		}
		i.MoveReg(i.decodeArgsReg2())
	case polkavm.Sbrk:
		if err := i.deductGas(polkavm.SbrkCost); err != nil {
			return 0, err
		}
		return 0, i.Sbrk(i.decodeArgsReg2())
	case polkavm.CountSetBits64:
		if err := i.deductGas(polkavm.CountSetBits64Cost); err != nil {
			return 0, err
		}
		i.CountSetBits64(i.decodeArgsReg2())
	case polkavm.CountSetBits32:
		if err := i.deductGas(polkavm.CountSetBits32Cost); err != nil {
			return 0, err
		}
		i.CountSetBits32(i.decodeArgsReg2())
	case polkavm.LeadingZeroBits64:
		if err := i.deductGas(polkavm.LeadingZeroBits64Cost); err != nil {
			return 0, err
		}
		i.LeadingZeroBits64(i.decodeArgsReg2())
	case polkavm.LeadingZeroBits32:
		if err := i.deductGas(polkavm.LeadingZeroBits32Cost); err != nil {
			return 0, err
		}
		i.LeadingZeroBits32(i.decodeArgsReg2())
	case polkavm.TrailingZeroBits64:
		if err := i.deductGas(polkavm.TrailingZeroBits64Cost); err != nil {
			return 0, err
		}
		i.TrailingZeroBits64(i.decodeArgsReg2())
	case polkavm.TrailingZeroBits32:
		if err := i.deductGas(polkavm.TrailingZeroBits32Cost); err != nil {
			return 0, err
		}
		i.TrailingZeroBits32(i.decodeArgsReg2())
	case polkavm.SignExtend8:
		if err := i.deductGas(polkavm.SignExtend8Cost); err != nil {
			return 0, err
		}
		i.SignExtend8(i.decodeArgsReg2())
	case polkavm.SignExtend16:
		if err := i.deductGas(polkavm.SignExtend16Cost); err != nil {
			return 0, err
		}
		i.SignExtend16(i.decodeArgsReg2())
	case polkavm.ZeroExtend16:
		if err := i.deductGas(polkavm.ZeroExtend16Cost); err != nil {
			return 0, err
		}
		i.ZeroExtend16(i.decodeArgsReg2())
	case polkavm.ReverseBytes:
		if err := i.deductGas(polkavm.ReverseBytesCost); err != nil {
			return 0, err
		}
		i.ReverseBytes(i.decodeArgsReg2())

	// (eq. A.29 v0.7.0)
	case polkavm.StoreIndirectU8:
		if err := i.deductGas(polkavm.StoreIndirectU8Cost); err != nil {
			return 0, err
		}
		return 0, i.StoreIndirectU8(i.decodeArgsReg2Imm())
	case polkavm.StoreIndirectU16:
		if err := i.deductGas(polkavm.StoreIndirectU16Cost); err != nil {
			return 0, err
		}
		return 0, i.StoreIndirectU16(i.decodeArgsReg2Imm())
	case polkavm.StoreIndirectU32:
		if err := i.deductGas(polkavm.StoreIndirectU32Cost); err != nil {
			return 0, err
		}
		return 0, i.StoreIndirectU32(i.decodeArgsReg2Imm())
	case polkavm.StoreIndirectU64:
		if err := i.deductGas(polkavm.StoreIndirectU64Cost); err != nil {
			return 0, err
		}
		return 0, i.StoreIndirectU64(i.decodeArgsReg2Imm())
	case polkavm.LoadIndirectU8:
		if err := i.deductGas(polkavm.LoadIndirectU8Cost); err != nil {
			return 0, err
		}
		return 0, i.LoadIndirectU8(i.decodeArgsReg2Imm())
	case polkavm.LoadIndirectI8:
		if err := i.deductGas(polkavm.LoadIndirectI8Cost); err != nil {
			return 0, err
		}
		return 0, i.LoadIndirectI8(i.decodeArgsReg2Imm())
	case polkavm.LoadIndirectU16:
		if err := i.deductGas(polkavm.LoadIndirectU16Cost); err != nil {
			return 0, err
		}
		return 0, i.LoadIndirectU16(i.decodeArgsReg2Imm())
	case polkavm.LoadIndirectI16:
		if err := i.deductGas(polkavm.LoadIndirectI16Cost); err != nil {
			return 0, err
		}
		return 0, i.LoadIndirectI16(i.decodeArgsReg2Imm())
	case polkavm.LoadIndirectU32:
		if err := i.deductGas(polkavm.LoadIndirectU32Cost); err != nil {
			return 0, err
		}
		return 0, i.LoadIndirectU32(i.decodeArgsReg2Imm())
	case polkavm.LoadIndirectI32:
		if err := i.deductGas(polkavm.LoadIndirectI32Cost); err != nil {
			return 0, err
		}
		return 0, i.LoadIndirectI32(i.decodeArgsReg2Imm())
	case polkavm.LoadIndirectU64:
		if err := i.deductGas(polkavm.LoadIndirectU64Cost); err != nil {
			return 0, err
		}
		return 0, i.LoadIndirectU64(i.decodeArgsReg2Imm())
	case polkavm.AddImm32:
		if err := i.deductGas(polkavm.AddImm32Cost); err != nil {
			return 0, err
		}
		i.AddImm32(i.decodeArgsReg2Imm())
	case polkavm.AndImm:
		if err := i.deductGas(polkavm.AndImmCost); err != nil {
			return 0, err
		}
		i.AndImm(i.decodeArgsReg2Imm())
	case polkavm.XorImm:
		if err := i.deductGas(polkavm.XorImmCost); err != nil {
			return 0, err
		}
		i.XorImm(i.decodeArgsReg2Imm())
	case polkavm.OrImm:
		if err := i.deductGas(polkavm.OrImmCost); err != nil {
			return 0, err
		}
		i.OrImm(i.decodeArgsReg2Imm())
	case polkavm.MulImm32:
		if err := i.deductGas(polkavm.MulImm32Cost); err != nil {
			return 0, err
		}
		i.MulImm32(i.decodeArgsReg2Imm())
	case polkavm.SetLessThanUnsignedImm:
		if err := i.deductGas(polkavm.SetLessThanUnsignedImmCost); err != nil {
			return 0, err
		}
		i.SetLessThanUnsignedImm(i.decodeArgsReg2Imm())
	case polkavm.SetLessThanSignedImm:
		if err := i.deductGas(polkavm.SetLessThanSignedImmCost); err != nil {
			return 0, err
		}
		i.SetLessThanSignedImm(i.decodeArgsReg2Imm())
	case polkavm.ShiftLogicalLeftImm32:
		if err := i.deductGas(polkavm.ShiftLogicalLeftImm32Cost); err != nil {
			return 0, err
		}
		i.ShiftLogicalLeftImm32(i.decodeArgsReg2Imm())
	case polkavm.ShiftLogicalRightImm32:
		if err := i.deductGas(polkavm.ShiftLogicalRightImm32Cost); err != nil {
			return 0, err
		}
		i.ShiftLogicalRightImm32(i.decodeArgsReg2Imm())
	case polkavm.ShiftArithmeticRightImm32:
		if err := i.deductGas(polkavm.ShiftArithmeticRightImm32Cost); err != nil {
			return 0, err
		}
		i.ShiftArithmeticRightImm32(i.decodeArgsReg2Imm())
	case polkavm.NegateAndAddImm32:
		if err := i.deductGas(polkavm.NegateAndAddImm32Cost); err != nil {
			return 0, err
		}
		i.NegateAndAddImm32(i.decodeArgsReg2Imm())
	case polkavm.SetGreaterThanUnsignedImm:
		if err := i.deductGas(polkavm.SetGreaterThanUnsignedImmCost); err != nil {
			return 0, err
		}
		i.SetGreaterThanUnsignedImm(i.decodeArgsReg2Imm())
	case polkavm.SetGreaterThanSignedImm:
		if err := i.deductGas(polkavm.SetGreaterThanSignedImmCost); err != nil {
			return 0, err
		}
		i.SetGreaterThanSignedImm(i.decodeArgsReg2Imm())
	case polkavm.ShiftLogicalLeftImmAlt32:
		if err := i.deductGas(polkavm.ShiftLogicalLeftImmAlt32Cost); err != nil {
			return 0, err
		}
		i.ShiftLogicalLeftImmAlt32(i.decodeArgsReg2Imm())
	case polkavm.ShiftArithmeticRightImmAlt32:
		if err := i.deductGas(polkavm.ShiftArithmeticRightImmAlt32Cost); err != nil {
			return 0, err
		}
		i.ShiftLogicalRightImmAlt32(i.decodeArgsReg2Imm())
	case polkavm.ShiftLogicalRightImmAlt32:
		if err := i.deductGas(polkavm.ShiftLogicalRightImmAlt32Cost); err != nil {
			return 0, err
		}
		i.ShiftArithmeticRightImmAlt32(i.decodeArgsReg2Imm())
	case polkavm.CmovIfZeroImm:
		if err := i.deductGas(polkavm.CmovIfZeroImmCost); err != nil {
			return 0, err
		}
		i.CmovIfZeroImm(i.decodeArgsReg2Imm())
	case polkavm.CmovIfNotZeroImm:
		if err := i.deductGas(polkavm.CmovIfNotZeroImmCost); err != nil {
			return 0, err
		}
		i.CmovIfNotZeroImm(i.decodeArgsReg2Imm())
	case polkavm.AddImm64:
		if err := i.deductGas(polkavm.AddImm64Cost); err != nil {
			return 0, err
		}
		i.AddImm64(i.decodeArgsReg2Imm())
	case polkavm.MulImm64:
		if err := i.deductGas(polkavm.MulImm64Cost); err != nil {
			return 0, err
		}
		i.MulImm64(i.decodeArgsReg2Imm())
	case polkavm.ShiftLogicalLeftImm64:
		if err := i.deductGas(polkavm.ShiftLogicalLeftImm64Cost); err != nil {
			return 0, err
		}
		i.ShiftLogicalLeftImm64(i.decodeArgsReg2Imm())
	case polkavm.ShiftLogicalRightImm64:
		if err := i.deductGas(polkavm.ShiftLogicalRightImm64Cost); err != nil {
			return 0, err
		}
		i.ShiftLogicalRightImm64(i.decodeArgsReg2Imm())
	case polkavm.ShiftArithmeticRightImm64:
		if err := i.deductGas(polkavm.ShiftArithmeticRightImm64Cost); err != nil {
			return 0, err
		}
		i.ShiftArithmeticRightImm64(i.decodeArgsReg2Imm())
	case polkavm.NegateAndAddImm64:
		if err := i.deductGas(polkavm.NegateAndAddImm64Cost); err != nil {
			return 0, err
		}
		i.NegateAndAddImm64(i.decodeArgsReg2Imm())
	case polkavm.ShiftLogicalLeftImmAlt64:
		if err := i.deductGas(polkavm.ShiftLogicalLeftImmAlt64Cost); err != nil {
			return 0, err
		}
		i.ShiftLogicalLeftImmAlt64(i.decodeArgsReg2Imm())
	case polkavm.ShiftLogicalRightImmAlt64:
		if err := i.deductGas(polkavm.ShiftLogicalRightImmAlt64Cost); err != nil {
			return 0, err
		}
		i.ShiftLogicalRightImmAlt64(i.decodeArgsReg2Imm())
	case polkavm.ShiftArithmeticRightImmAlt64:
		if err := i.deductGas(polkavm.ShiftArithmeticRightImmAlt64Cost); err != nil {
			return 0, err
		}
		i.ShiftArithmeticRightImmAlt64(i.decodeArgsReg2Imm())
	case polkavm.RotR64Imm:
		if err := i.deductGas(polkavm.RotR64ImmCost); err != nil {
			return 0, err
		}
		i.RotateRight64Imm(i.decodeArgsReg2Imm())
	case polkavm.RotR64ImmAlt:
		if err := i.deductGas(polkavm.RotR64ImmAltCost); err != nil {
			return 0, err
		}
		i.RotateRight64ImmAlt(i.decodeArgsReg2Imm())
	case polkavm.RotR32Imm:
		if err := i.deductGas(polkavm.RotR32ImmCost); err != nil {
			return 0, err
		}
		i.RotateRight32Imm(i.decodeArgsReg2Imm())
	case polkavm.RotR32ImmAlt:
		if err := i.deductGas(polkavm.RotR32ImmAltCost); err != nil {
			return 0, err
		}
		i.RotateRight32ImmAlt(i.decodeArgsReg2Imm())

	// (eq. A.30 v0.7.0)
	case polkavm.BranchEq:
		if err := i.deductGas(polkavm.BranchEqCost); err != nil {
			return 0, err
		}
		return 0, i.BranchEq(i.decodeArgsReg2Offset())
	case polkavm.BranchNotEq:
		if err := i.deductGas(polkavm.BranchNotEqCost); err != nil {
			return 0, err
		}
		return 0, i.BranchNotEq(i.decodeArgsReg2Offset())
	case polkavm.BranchLessUnsigned:
		if err := i.deductGas(polkavm.BranchLessUnsignedCost); err != nil {
			return 0, err
		}
		return 0, i.BranchLessUnsigned(i.decodeArgsReg2Offset())
	case polkavm.BranchLessSigned:
		if err := i.deductGas(polkavm.BranchLessSignedCost); err != nil {
			return 0, err
		}
		return 0, i.BranchLessSigned(i.decodeArgsReg2Offset())
	case polkavm.BranchGreaterOrEqualUnsigned:
		if err := i.deductGas(polkavm.BranchGreaterOrEqualUnsignedCost); err != nil {
			return 0, err
		}
		return 0, i.BranchGreaterOrEqualUnsigned(i.decodeArgsReg2Offset())
	case polkavm.BranchGreaterOrEqualSigned:
		if err := i.deductGas(polkavm.BranchGreaterOrEqualSignedCost); err != nil {
			return 0, err
		}
		return 0, i.BranchGreaterOrEqualSigned(i.decodeArgsReg2Offset())

	// (eq. A.31 v0.7.0)
	case polkavm.LoadImmAndJumpIndirect:
		if err := i.deductGas(polkavm.LoadImmAndJumpIndirectCost); err != nil {
			return 0, err
		}
		return 0, i.LoadImmAndJumpIndirect(i.decodeArgsReg2Imm2())

	// (eq. A.32 v0.7.0)
	case polkavm.Add32:
		if err := i.deductGas(polkavm.Add32Cost); err != nil {
			return 0, err
		}
		i.Add32(i.decodeArgsReg3())
	case polkavm.Sub32:
		if err := i.deductGas(polkavm.Sub32Cost); err != nil {
			return 0, err
		}
		i.Sub32(i.decodeArgsReg3())
	case polkavm.Mul32:
		if err := i.deductGas(polkavm.Mul32Cost); err != nil {
			return 0, err
		}
		i.Mul32(i.decodeArgsReg3())
	case polkavm.DivUnsigned32:
		if err := i.deductGas(polkavm.DivUnsigned32Cost); err != nil {
			return 0, err
		}
		i.DivUnsigned32(i.decodeArgsReg3())
	case polkavm.DivSigned32:
		if err := i.deductGas(polkavm.DivSigned32Cost); err != nil {
			return 0, err
		}
		i.DivSigned32(i.decodeArgsReg3())
	case polkavm.RemUnsigned32:
		if err := i.deductGas(polkavm.RemUnsigned32Cost); err != nil {
			return 0, err
		}
		i.RemUnsigned32(i.decodeArgsReg3())
	case polkavm.RemSigned32:
		if err := i.deductGas(polkavm.RemSigned32Cost); err != nil {
			return 0, err
		}
		i.RemSigned32(i.decodeArgsReg3())
	case polkavm.ShiftLogicalLeft32:
		if err := i.deductGas(polkavm.ShiftLogicalLeft32Cost); err != nil {
			return 0, err
		}
		i.ShiftLogicalLeft32(i.decodeArgsReg3())
	case polkavm.ShiftLogicalRight32:
		if err := i.deductGas(polkavm.ShiftLogicalRight32Cost); err != nil {
			return 0, err
		}
		i.ShiftLogicalRight32(i.decodeArgsReg3())
	case polkavm.ShiftArithmeticRight32:
		if err := i.deductGas(polkavm.ShiftArithmeticRight32Cost); err != nil {
			return 0, err
		}
		i.ShiftArithmeticRight32(i.decodeArgsReg3())
	case polkavm.Add64:
		if err := i.deductGas(polkavm.Add64Cost); err != nil {
			return 0, err
		}
		i.Add64(i.decodeArgsReg3())
	case polkavm.Sub64:
		if err := i.deductGas(polkavm.Sub64Cost); err != nil {
			return 0, err
		}
		i.Sub64(i.decodeArgsReg3())
	case polkavm.Mul64:
		if err := i.deductGas(polkavm.Mul64Cost); err != nil {
			return 0, err
		}
		i.Mul64(i.decodeArgsReg3())
	case polkavm.DivUnsigned64:
		if err := i.deductGas(polkavm.DivUnsigned64Cost); err != nil {
			return 0, err
		}
		i.DivUnsigned64(i.decodeArgsReg3())
	case polkavm.DivSigned64:
		if err := i.deductGas(polkavm.DivSigned64Cost); err != nil {
			return 0, err
		}
		i.DivSigned64(i.decodeArgsReg3())
	case polkavm.RemUnsigned64:
		if err := i.deductGas(polkavm.RemUnsigned64Cost); err != nil {
			return 0, err
		}
		i.RemUnsigned64(i.decodeArgsReg3())
	case polkavm.RemSigned64:
		if err := i.deductGas(polkavm.RemSigned64Cost); err != nil {
			return 0, err
		}
		i.RemSigned64(i.decodeArgsReg3())
	case polkavm.ShiftLogicalLeft64:
		if err := i.deductGas(polkavm.ShiftLogicalLeft64Cost); err != nil {
			return 0, err
		}
		i.ShiftLogicalLeft64(i.decodeArgsReg3())
	case polkavm.ShiftLogicalRight64:
		if err := i.deductGas(polkavm.ShiftLogicalRight64Cost); err != nil {
			return 0, err
		}
		i.ShiftLogicalRight64(i.decodeArgsReg3())
	case polkavm.ShiftArithmeticRight64:
		if err := i.deductGas(polkavm.ShiftArithmeticRight64Cost); err != nil {
			return 0, err
		}
		i.ShiftArithmeticRight64(i.decodeArgsReg3())
	case polkavm.And:
		if err := i.deductGas(polkavm.AndCost); err != nil {
			return 0, err
		}
		i.And(i.decodeArgsReg3())
	case polkavm.Xor:
		if err := i.deductGas(polkavm.XorCost); err != nil {
			return 0, err
		}
		i.Xor(i.decodeArgsReg3())
	case polkavm.Or:
		if err := i.deductGas(polkavm.OrCost); err != nil {
			return 0, err
		}
		i.Or(i.decodeArgsReg3())
	case polkavm.MulUpperSignedSigned:
		if err := i.deductGas(polkavm.MulUpperSignedSignedCost); err != nil {
			return 0, err
		}
		i.MulUpperSignedSigned(i.decodeArgsReg3())
	case polkavm.MulUpperUnsignedUnsigned:
		if err := i.deductGas(polkavm.MulUpperUnsignedUnsignedCost); err != nil {
			return 0, err
		}
		i.MulUpperUnsignedUnsigned(i.decodeArgsReg3())
	case polkavm.MulUpperSignedUnsigned:
		if err := i.deductGas(polkavm.MulUpperSignedUnsignedCost); err != nil {
			return 0, err
		}
		i.MulUpperSignedUnsigned(i.decodeArgsReg3())
	case polkavm.SetLessThanUnsigned:
		if err := i.deductGas(polkavm.SetLessThanUnsignedCost); err != nil {
			return 0, err
		}
		i.SetLessThanUnsigned(i.decodeArgsReg3())
	case polkavm.SetLessThanSigned:
		if err := i.deductGas(polkavm.SetLessThanSignedCost); err != nil {
			return 0, err
		}
		i.SetLessThanSigned(i.decodeArgsReg3())
	case polkavm.CmovIfZero:
		if err := i.deductGas(polkavm.CmovIfZeroCost); err != nil {
			return 0, err
		}
		i.CmovIfZero(i.decodeArgsReg3())
	case polkavm.CmovIfNotZero:
		if err := i.deductGas(polkavm.CmovIfNotZeroCost); err != nil {
			return 0, err
		}
		i.CmovIfNotZero(i.decodeArgsReg3())
	case polkavm.RotL64:
		if err := i.deductGas(polkavm.RotL64Cost); err != nil {
			return 0, err
		}
		i.RotateLeft64(i.decodeArgsReg3())
	case polkavm.RotL32:
		if err := i.deductGas(polkavm.RotL32Cost); err != nil {
			return 0, err
		}
		i.RotateLeft32(i.decodeArgsReg3())
	case polkavm.RotR64:
		if err := i.deductGas(polkavm.RotR64Cost); err != nil {
			return 0, err
		}
		i.RotateRight64(i.decodeArgsReg3())
	case polkavm.RotR32:
		if err := i.deductGas(polkavm.RotR32Cost); err != nil {
			return 0, err
		}
		i.RotateRight32(i.decodeArgsReg3())
	case polkavm.AndInv:
		if err := i.deductGas(polkavm.AndInvCost); err != nil {
			return 0, err
		}
		i.AndInverted(i.decodeArgsReg3())
	case polkavm.OrInv:
		if err := i.deductGas(polkavm.OrInvCost); err != nil {
			return 0, err
		}
		i.OrInverted(i.decodeArgsReg3())
	case polkavm.Xnor:
		if err := i.deductGas(polkavm.XnorCost); err != nil {
			return 0, err
		}
		i.Xnor(i.decodeArgsReg3())
	case polkavm.Max:
		if err := i.deductGas(polkavm.MaxCost); err != nil {
			return 0, err
		}
		i.Max(i.decodeArgsReg3())
	case polkavm.MaxU:
		if err := i.deductGas(polkavm.MaxUCost); err != nil {
			return 0, err
		}
		i.MaxUnsigned(i.decodeArgsReg3())
	case polkavm.Min:
		if err := i.deductGas(polkavm.MinCost); err != nil {
			return 0, err
		}
		i.Min(i.decodeArgsReg3())
	case polkavm.MinU:
		if err := i.deductGas(polkavm.MinUCost); err != nil {
			return 0, err
		}
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
	if instr := i.instructionsCache[i.instructionCounter]; instr != nil {
		return instr.val[0]
	}
	// let lX = min(4, ℓ)
	lenX := min(4, i.skipLen)

	// νX ≡ X_lX(E−1lX (ζı+1⋅⋅⋅+lX))
	valueX = sext(jam.DecodeUint64(i.code[i.instructionCounter+1:i.instructionCounter+1+lenX]), lenX)
	i.instructionsCache[i.instructionCounter] = &instructionCache{val: [2]uint64{valueX}}
	return valueX
}

func (i *Instance) decodeArgsRegImmExt() (regA polkavm.Reg, valueX uint64) {
	if instr := i.instructionsCache[i.instructionCounter]; instr != nil {
		return instr.reg[0], instr.val[0]
	}
	// let rA = min(12, ζı+1 mod 16), φ′A ≡ φ′rA
	regA = polkavm.Reg(min(12, i.code[i.instructionCounter+1]%16))
	// νX ≡ E−1_8(ζı+2⋅⋅⋅+8)
	valueX = jam.DecodeUint64(i.code[i.instructionCounter+2 : i.instructionCounter+10])
	i.instructionsCache[i.instructionCounter] = &instructionCache{reg: [3]polkavm.Reg{regA}, val: [2]uint64{valueX}}
	return regA, valueX
}

func (i *Instance) decodeArgsImm2() (valueX, valueY uint64) {
	if instr := i.instructionsCache[i.instructionCounter]; instr != nil {
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
	i.instructionsCache[i.instructionCounter] = &instructionCache{val: [2]uint64{valueX, valueY}}
	return valueX, valueY
}

func (i *Instance) decodeArgsOffset() (valueX uint64) {
	if instr := i.instructionsCache[i.instructionCounter]; instr != nil {
		return instr.val[0]
	}
	// let lX = min(4, ℓ)
	lenX := min(4, i.skipLen)

	// νX ≡ ı + Z_lX (E−1_lX(ζı+1⋅⋅⋅+lX))
	valueX = uint64(int64(i.instructionCounter) + signed(jam.DecodeUint64(i.code[i.instructionCounter+1:i.instructionCounter+1+lenX]), lenX))
	i.instructionsCache[i.instructionCounter] = &instructionCache{val: [2]uint64{valueX}}
	return valueX
}

func (i *Instance) decodeArgsRegImm() (regA polkavm.Reg, valueX uint64) {
	if instr := i.instructionsCache[i.instructionCounter]; instr != nil {
		return instr.reg[0], instr.val[0]
	}
	// let lX = min(4, max(0, ℓ − 1))
	lenX := uint64(min(4, max(0, int(i.skipLen)-1)))
	// let rA = min(12, ζı+1 mod 16), φ′A ≡ φ′rA
	regA = polkavm.Reg(min(12, i.code[i.instructionCounter+1]%16))

	// νX ≡ X_lX(E−1_lX(ζı+2...+lX))
	valueX = sext(jam.DecodeUint64(i.code[i.instructionCounter+2:i.instructionCounter+2+lenX]), lenX)
	i.instructionsCache[i.instructionCounter] = &instructionCache{reg: [3]polkavm.Reg{regA}, val: [2]uint64{valueX}}
	return regA, valueX
}

func (i *Instance) decodeArgsRegImm2() (regA polkavm.Reg, valueX, valueY uint64) {
	if instr := i.instructionsCache[i.instructionCounter]; instr != nil {
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
	i.instructionsCache[i.instructionCounter] = &instructionCache{reg: [3]polkavm.Reg{regA}, val: [2]uint64{valueX, valueY}}
	return regA, valueX, valueY
}

func (i *Instance) decodeArgsRegImmOffset() (regA polkavm.Reg, valueX, valueY uint64) {
	if instr := i.instructionsCache[i.instructionCounter]; instr != nil {
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
	i.instructionsCache[i.instructionCounter] = &instructionCache{reg: [3]polkavm.Reg{regA}, val: [2]uint64{valueX, valueY}}
	return regA, valueX, valueY
}

func (i *Instance) decodeArgsReg2() (regDst, regA polkavm.Reg) {
	if instr := i.instructionsCache[i.instructionCounter]; instr != nil {
		return instr.reg[0], instr.reg[1]
	}
	// let rD = min(12, (ζı+1) mod 16) , φD ≡ φrD , φ′D ≡ φ′rD
	regDst = polkavm.Reg(min(12, i.code[i.instructionCounter+1]%16))

	// let rA = min(12, ⌊ ζı+1 / 16 ⌋) , φA ≡ φrA , φ′A ≡ φ′rA
	regA = polkavm.Reg(min(12, i.code[i.instructionCounter+1]/16))
	i.instructionsCache[i.instructionCounter] = &instructionCache{reg: [3]polkavm.Reg{regDst, regA}}
	return regDst, regA
}

func (i *Instance) decodeArgsReg2Imm() (regA, regB polkavm.Reg, valueX uint64) {
	if instr := i.instructionsCache[i.instructionCounter]; instr != nil {
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
	i.instructionsCache[i.instructionCounter] = &instructionCache{reg: [3]polkavm.Reg{regA, regB}, val: [2]uint64{valueX}}
	return regA, regB, valueX
}

func (i *Instance) decodeArgsReg2Offset() (regA, regB polkavm.Reg, valueX uint64) {
	if instr := i.instructionsCache[i.instructionCounter]; instr != nil {
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
	i.instructionsCache[i.instructionCounter] = &instructionCache{reg: [3]polkavm.Reg{regA, regB}, val: [2]uint64{valueX}}
	return regA, regB, valueX
}

func (i *Instance) decodeArgsReg2Imm2() (regA, regB polkavm.Reg, valueX, valueY uint64) {
	if instr := i.instructionsCache[i.instructionCounter]; instr != nil {
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

	i.instructionsCache[i.instructionCounter] = &instructionCache{reg: [3]polkavm.Reg{regA, regB}, val: [2]uint64{valueX, valueY}}
	return regA, regB, valueX, valueY
}

func (i *Instance) decodeArgsReg3() (regDst, regA, regB polkavm.Reg) {
	if instr := i.instructionsCache[i.instructionCounter]; instr != nil {
		return instr.reg[0], instr.reg[1], instr.reg[2]
	}
	// let rA = min(12, (ζı+1) mod 16), φA ≡ φrA, φ′A ≡ φ′rA
	regA = polkavm.Reg(min(12, i.code[i.instructionCounter+1]%16))
	// let rB = min(12, ⌊ ζı+1 / 16 ⌋), φB ≡ φrB, φ′B ≡ φ′rB
	regB = polkavm.Reg(min(12, i.code[i.instructionCounter+1]/16))
	// let rD = min(12, ζı+2), φD ≡ φrD, φ′D ≡ φ′rD
	regDst = polkavm.Reg(min(12, i.code[i.instructionCounter+2]))

	i.instructionsCache[i.instructionCounter] = &instructionCache{reg: [3]polkavm.Reg{regDst, regA, regB}}
	return regDst, regA, regB
}
