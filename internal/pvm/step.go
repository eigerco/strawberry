package pvm

import (
	"github.com/eigerco/strawberry/pkg/serialization/codec/jam"
)

// step Ψ1(B, B, ⟦NR⟧, NR, NG, ⟦NR⟧13, M) → ({☇, ∎, ▸} ∪ {F,-h} × NR, NR, ZG, ⟦NR⟧13, M) (A.6 v0.7.2)
func (i *Instance) step() (uint64, error) {
	codeLength := uint64(len(i.code))
	// ℓ ≡ skip(ı) (eq. A.20 v0.7.2)
	// precomputed skip length
	if i.instructionCounter < uint64(len(i.skipLengths)) {
		i.skipLen = uint64(i.skipLengths[i.instructionCounter])
	} else {
		i.skipLen = 0
	}

	// ζ ≡ c ⌢ [0, 0, ... ] (eq. A.4 v0.7.2)
	// We cannot add infinite items to a slice, but we simulate this by defaulting to trap opcode
	opcode := Trap

	if i.instructionCounter < codeLength {
		opcode = Opcode(i.code[i.instructionCounter])
	}

	// ϱ′ = ϱ − ϱ∆ (eq. A.9 v0.7.2)
	switch opcode {
	case Trap:
		if err := i.deductGas(TrapCost); err != nil {
			return 0, err
		}
		return 0, i.Trap()
	case Fallthrough:
		if err := i.deductGas(FallthroughCost); err != nil {
			return 0, err
		}
		i.Fallthrough()

	// (eq. A.21 v0.7.0)
	case Ecalli:
		if err := i.deductGas(EcalliCost); err != nil {
			return 0, err
		}
		// ε = ħ × νX
		return i.decodeArgsImm(), ErrHostCall

	// (eq. A.22 v0.7.0)
	case LoadImm64:
		if err := i.deductGas(LoadImm64Cost); err != nil {
			return 0, err
		}
		i.LoadImm64(i.decodeArgsRegImmExt())

	// (eq. A.23 v0.7.0)
	case StoreImmU8:
		if err := i.deductGas(StoreImmU8Cost); err != nil {
			return 0, err
		}
		return 0, i.StoreImmU8(i.decodeArgsImm2())
	case StoreImmU16:
		if err := i.deductGas(StoreImmU16Cost); err != nil {
			return 0, err
		}
		return 0, i.StoreImmU16(i.decodeArgsImm2())
	case StoreImmU32:
		if err := i.deductGas(StoreImmU32Cost); err != nil {
			return 0, err
		}
		return 0, i.StoreImmU32(i.decodeArgsImm2())
	case StoreImmU64:
		if err := i.deductGas(StoreImmU64Cost); err != nil {
			return 0, err
		}
		return 0, i.StoreImmU64(i.decodeArgsImm2())

	// (eq. A.24 v0.7.0)
	case Jump:
		if err := i.deductGas(JumpCost); err != nil {
			return 0, err
		}
		return 0, i.Jump(i.decodeArgsOffset())

	// (eq. A.25 v0.7.0)
	case JumpInd:
		if err := i.deductGas(JumpIndirectCost); err != nil {
			return 0, err
		}
		return 0, i.JumpInd(i.decodeArgsRegImm())
	case LoadImm:
		if err := i.deductGas(LoadImmCost); err != nil {
			return 0, err
		}
		i.LoadImm(i.decodeArgsRegImm())
	case LoadU8:
		if err := i.deductGas(LoadU8Cost); err != nil {
			return 0, err
		}
		return 0, i.LoadU8(i.decodeArgsRegImm())
	case LoadI8:
		if err := i.deductGas(LoadI8Cost); err != nil {
			return 0, err
		}
		return 0, i.LoadI8(i.decodeArgsRegImm())
	case LoadU16:
		if err := i.deductGas(LoadU16Cost); err != nil {
			return 0, err
		}
		return 0, i.LoadU16(i.decodeArgsRegImm())
	case LoadI16:
		if err := i.deductGas(LoadI16Cost); err != nil {
			return 0, err
		}
		return 0, i.LoadI16(i.decodeArgsRegImm())
	case LoadU32:
		if err := i.deductGas(LoadU32Cost); err != nil {
			return 0, err
		}
		return 0, i.LoadU32(i.decodeArgsRegImm())
	case LoadI32:
		if err := i.deductGas(LoadI32Cost); err != nil {
			return 0, err
		}
		return 0, i.LoadI32(i.decodeArgsRegImm())
	case LoadU64:
		if err := i.deductGas(LoadU64Cost); err != nil {
			return 0, err
		}
		return 0, i.LoadU64(i.decodeArgsRegImm())
	case StoreU8:
		if err := i.deductGas(StoreU8Cost); err != nil {
			return 0, err
		}
		return 0, i.StoreU8(i.decodeArgsRegImm())
	case StoreU16:
		if err := i.deductGas(StoreU16Cost); err != nil {
			return 0, err
		}
		return 0, i.StoreU16(i.decodeArgsRegImm())
	case StoreU32:
		if err := i.deductGas(StoreU32Cost); err != nil {
			return 0, err
		}
		return 0, i.StoreU32(i.decodeArgsRegImm())
	case StoreU64:
		if err := i.deductGas(StoreU64Cost); err != nil {
			return 0, err
		}
		return 0, i.StoreU64(i.decodeArgsRegImm())

	// (eq. A.26 v0.7.0)
	case StoreImmIndU8:
		if err := i.deductGas(StoreImmIndirectU8Cost); err != nil {
			return 0, err
		}
		return 0, i.StoreImmIndU8(i.decodeArgsRegImm2())
	case StoreImmIndU16:
		if err := i.deductGas(StoreImmIndirectU16Cost); err != nil {
			return 0, err
		}
		return 0, i.StoreImmIndU16(i.decodeArgsRegImm2())
	case StoreImmIndU32:
		if err := i.deductGas(StoreImmIndirectU32Cost); err != nil {
			return 0, err
		}
		return 0, i.StoreImmIndU32(i.decodeArgsRegImm2())
	case StoreImmIndU64:
		if err := i.deductGas(StoreImmIndirectU64Cost); err != nil {
			return 0, err
		}
		return 0, i.StoreImmIndU64(i.decodeArgsRegImm2())

	// (eq. A.27 v0.7.0)
	case LoadImmJump:
		if err := i.deductGas(LoadImmAndJumpCost); err != nil {
			return 0, err
		}
		return 0, i.LoadImmJump(i.decodeArgsRegImmOffset())
	case BranchEqImm:
		if err := i.deductGas(BranchEqImmCost); err != nil {
			return 0, err
		}
		return 0, i.BranchEqImm(i.decodeArgsRegImmOffset())
	case BranchNeImm:
		if err := i.deductGas(BranchNotEqImmCost); err != nil {
			return 0, err
		}
		return 0, i.BranchNeImm(i.decodeArgsRegImmOffset())
	case BranchLtUImm:
		if err := i.deductGas(BranchLessUnsignedImmCost); err != nil {
			return 0, err
		}
		return 0, i.BranchLtUImm(i.decodeArgsRegImmOffset())
	case BranchLeUImm:
		if err := i.deductGas(BranchLessOrEqualUnsignedImmCost); err != nil {
			return 0, err
		}
		return 0, i.BranchLeUImm(i.decodeArgsRegImmOffset())
	case BranchGeUImm:
		if err := i.deductGas(BranchGreaterOrEqualUnsignedImmCost); err != nil {
			return 0, err
		}
		return 0, i.BranchGeUImm(i.decodeArgsRegImmOffset())
	case BranchGtUImm:
		if err := i.deductGas(BranchGreaterUnsignedImmCost); err != nil {
			return 0, err
		}
		return 0, i.BranchGtUImm(i.decodeArgsRegImmOffset())
	case BranchLtSImm:
		if err := i.deductGas(BranchLessSignedImmCost); err != nil {
			return 0, err
		}
		return 0, i.BranchLtSImm(i.decodeArgsRegImmOffset())
	case BranchLeSImm:
		if err := i.deductGas(BranchLessOrEqualSignedImmCost); err != nil {
			return 0, err
		}
		return 0, i.BranchLeSImm(i.decodeArgsRegImmOffset())
	case BranchGeSImm:
		if err := i.deductGas(BranchGreaterOrEqualSignedImmCost); err != nil {
			return 0, err
		}
		return 0, i.BranchGeSImm(i.decodeArgsRegImmOffset())
	case BranchGtSImm:
		if err := i.deductGas(BranchGreaterSignedImmCost); err != nil {
			return 0, err
		}
		return 0, i.BranchGtSImm(i.decodeArgsRegImmOffset())

	// (eq. A.28 v0.7.0)
	case MoveReg:
		if err := i.deductGas(MoveRegCost); err != nil {
			return 0, err
		}
		i.MoveReg(i.decodeArgsReg2())
	case Sbrk:
		if err := i.deductGas(SbrkCost); err != nil {
			return 0, err
		}
		return 0, i.Sbrk(i.decodeArgsReg2())
	case CountSetBits64:
		if err := i.deductGas(CountSetBits64Cost); err != nil {
			return 0, err
		}
		i.CountSetBits64(i.decodeArgsReg2())
	case CountSetBits32:
		if err := i.deductGas(CountSetBits32Cost); err != nil {
			return 0, err
		}
		i.CountSetBits32(i.decodeArgsReg2())
	case LeadingZeroBits64:
		if err := i.deductGas(LeadingZeroBits64Cost); err != nil {
			return 0, err
		}
		i.LeadingZeroBits64(i.decodeArgsReg2())
	case LeadingZeroBits32:
		if err := i.deductGas(LeadingZeroBits32Cost); err != nil {
			return 0, err
		}
		i.LeadingZeroBits32(i.decodeArgsReg2())
	case TrailingZeroBits64:
		if err := i.deductGas(TrailingZeroBits64Cost); err != nil {
			return 0, err
		}
		i.TrailingZeroBits64(i.decodeArgsReg2())
	case TrailingZeroBits32:
		if err := i.deductGas(TrailingZeroBits32Cost); err != nil {
			return 0, err
		}
		i.TrailingZeroBits32(i.decodeArgsReg2())
	case SignExtend8:
		if err := i.deductGas(SignExtend8Cost); err != nil {
			return 0, err
		}
		i.SignExtend8(i.decodeArgsReg2())
	case SignExtend16:
		if err := i.deductGas(SignExtend16Cost); err != nil {
			return 0, err
		}
		i.SignExtend16(i.decodeArgsReg2())
	case ZeroExtend16:
		if err := i.deductGas(ZeroExtend16Cost); err != nil {
			return 0, err
		}
		i.ZeroExtend16(i.decodeArgsReg2())
	case ReverseBytes:
		if err := i.deductGas(ReverseBytesCost); err != nil {
			return 0, err
		}
		i.ReverseBytes(i.decodeArgsReg2())

	// (eq. A.29 v0.7.0)
	case StoreIndU8:
		if err := i.deductGas(StoreIndirectU8Cost); err != nil {
			return 0, err
		}
		return 0, i.StoreIndU8(i.decodeArgsReg2Imm())
	case StoreIndU16:
		if err := i.deductGas(StoreIndirectU16Cost); err != nil {
			return 0, err
		}
		return 0, i.StoreIndU16(i.decodeArgsReg2Imm())
	case StoreIndU32:
		if err := i.deductGas(StoreIndirectU32Cost); err != nil {
			return 0, err
		}
		return 0, i.StoreIndU32(i.decodeArgsReg2Imm())
	case StoreIndU64:
		if err := i.deductGas(StoreIndirectU64Cost); err != nil {
			return 0, err
		}
		return 0, i.StoreIndU64(i.decodeArgsReg2Imm())
	case LoadIndU8:
		if err := i.deductGas(LoadIndirectU8Cost); err != nil {
			return 0, err
		}
		return 0, i.LoadIndU8(i.decodeArgsReg2Imm())
	case LoadIndI8:
		if err := i.deductGas(LoadIndirectI8Cost); err != nil {
			return 0, err
		}
		return 0, i.LoadIndI8(i.decodeArgsReg2Imm())
	case LoadIndU16:
		if err := i.deductGas(LoadIndirectU16Cost); err != nil {
			return 0, err
		}
		return 0, i.LoadIndU16(i.decodeArgsReg2Imm())
	case LoadIndI16:
		if err := i.deductGas(LoadIndirectI16Cost); err != nil {
			return 0, err
		}
		return 0, i.LoadIndI16(i.decodeArgsReg2Imm())
	case LoadIndU32:
		if err := i.deductGas(LoadIndirectU32Cost); err != nil {
			return 0, err
		}
		return 0, i.LoadIndU32(i.decodeArgsReg2Imm())
	case LoadIndI32:
		if err := i.deductGas(LoadIndirectI32Cost); err != nil {
			return 0, err
		}
		return 0, i.LoadIndI32(i.decodeArgsReg2Imm())
	case LoadIndU64:
		if err := i.deductGas(LoadIndirectU64Cost); err != nil {
			return 0, err
		}
		return 0, i.LoadIndU64(i.decodeArgsReg2Imm())
	case AddImm32:
		if err := i.deductGas(AddImm32Cost); err != nil {
			return 0, err
		}
		i.AddImm32(i.decodeArgsReg2Imm())
	case AndImm:
		if err := i.deductGas(AndImmCost); err != nil {
			return 0, err
		}
		i.AndImm(i.decodeArgsReg2Imm())
	case XorImm:
		if err := i.deductGas(XorImmCost); err != nil {
			return 0, err
		}
		i.XorImm(i.decodeArgsReg2Imm())
	case OrImm:
		if err := i.deductGas(OrImmCost); err != nil {
			return 0, err
		}
		i.OrImm(i.decodeArgsReg2Imm())
	case MulImm32:
		if err := i.deductGas(MulImm32Cost); err != nil {
			return 0, err
		}
		i.MulImm32(i.decodeArgsReg2Imm())
	case SetLtUImm:
		if err := i.deductGas(SetLessThanUnsignedImmCost); err != nil {
			return 0, err
		}
		i.SetLtUImm(i.decodeArgsReg2Imm())
	case SetLtSImm:
		if err := i.deductGas(SetLessThanSignedImmCost); err != nil {
			return 0, err
		}
		i.SetLtSImm(i.decodeArgsReg2Imm())
	case ShloLImm32:
		if err := i.deductGas(ShiftLogicalLeftImm32Cost); err != nil {
			return 0, err
		}
		i.ShloLImm32(i.decodeArgsReg2Imm())
	case ShloRImm32:
		if err := i.deductGas(ShiftLogicalRightImm32Cost); err != nil {
			return 0, err
		}
		i.ShloRImm32(i.decodeArgsReg2Imm())
	case SharRImm32:
		if err := i.deductGas(ShiftArithmeticRightImm32Cost); err != nil {
			return 0, err
		}
		i.SharRImm32(i.decodeArgsReg2Imm())
	case NegAddImm32:
		if err := i.deductGas(NegateAndAddImm32Cost); err != nil {
			return 0, err
		}
		i.NegAddImm32(i.decodeArgsReg2Imm())
	case SetGtUImm:
		if err := i.deductGas(SetGreaterThanUnsignedImmCost); err != nil {
			return 0, err
		}
		i.SetGtUImm(i.decodeArgsReg2Imm())
	case SetGtSImm:
		if err := i.deductGas(SetGreaterThanSignedImmCost); err != nil {
			return 0, err
		}
		i.SetGtSImm(i.decodeArgsReg2Imm())
	case ShloLImmAlt32:
		if err := i.deductGas(ShiftLogicalLeftImmAlt32Cost); err != nil {
			return 0, err
		}
		i.ShloLImmAlt32(i.decodeArgsReg2Imm())
	case ShloRImmAlt32:
		if err := i.deductGas(ShiftArithmeticRightImmAlt32Cost); err != nil {
			return 0, err
		}
		i.SharRImmAlt32(i.decodeArgsReg2Imm())
	case SharRImmAlt32:
		if err := i.deductGas(ShiftLogicalRightImmAlt32Cost); err != nil {
			return 0, err
		}
		i.ShloRImmAlt32(i.decodeArgsReg2Imm())
	case CmovIzImm:
		if err := i.deductGas(CmovIfZeroImmCost); err != nil {
			return 0, err
		}
		i.CmovIzImm(i.decodeArgsReg2Imm())
	case CmovNzImm:
		if err := i.deductGas(CmovIfNotZeroImmCost); err != nil {
			return 0, err
		}
		i.CmovNzImm(i.decodeArgsReg2Imm())
	case AddImm64:
		if err := i.deductGas(AddImm64Cost); err != nil {
			return 0, err
		}
		i.AddImm64(i.decodeArgsReg2Imm())
	case MulImm64:
		if err := i.deductGas(MulImm64Cost); err != nil {
			return 0, err
		}
		i.MulImm64(i.decodeArgsReg2Imm())
	case ShloLImm64:
		if err := i.deductGas(ShiftLogicalLeftImm64Cost); err != nil {
			return 0, err
		}
		i.ShloLImm64(i.decodeArgsReg2Imm())
	case ShloRImm64:
		if err := i.deductGas(ShiftLogicalRightImm64Cost); err != nil {
			return 0, err
		}
		i.ShloRImm64(i.decodeArgsReg2Imm())
	case SharRImm64:
		if err := i.deductGas(ShiftArithmeticRightImm64Cost); err != nil {
			return 0, err
		}
		i.SharRImm64(i.decodeArgsReg2Imm())
	case NegAddImm64:
		if err := i.deductGas(NegateAndAddImm64Cost); err != nil {
			return 0, err
		}
		i.NegAddImm64(i.decodeArgsReg2Imm())
	case ShloLImmAlt64:
		if err := i.deductGas(ShiftLogicalLeftImmAlt64Cost); err != nil {
			return 0, err
		}
		i.ShloLImmAlt64(i.decodeArgsReg2Imm())
	case ShloRImmAlt64:
		if err := i.deductGas(ShiftLogicalRightImmAlt64Cost); err != nil {
			return 0, err
		}
		i.ShloRImmAlt64(i.decodeArgsReg2Imm())
	case SharRImmAlt64:
		if err := i.deductGas(ShiftArithmeticRightImmAlt64Cost); err != nil {
			return 0, err
		}
		i.SharRImmAlt64(i.decodeArgsReg2Imm())
	case RotR64Imm:
		if err := i.deductGas(RotR64ImmCost); err != nil {
			return 0, err
		}
		i.RotateRight64Imm(i.decodeArgsReg2Imm())
	case RotR64ImmAlt:
		if err := i.deductGas(RotR64ImmAltCost); err != nil {
			return 0, err
		}
		i.RotateRight64ImmAlt(i.decodeArgsReg2Imm())
	case RotR32Imm:
		if err := i.deductGas(RotR32ImmCost); err != nil {
			return 0, err
		}
		i.RotateRight32Imm(i.decodeArgsReg2Imm())
	case RotR32ImmAlt:
		if err := i.deductGas(RotR32ImmAltCost); err != nil {
			return 0, err
		}
		i.RotateRight32ImmAlt(i.decodeArgsReg2Imm())

	// (eq. A.30 v0.7.0)
	case BranchEq:
		if err := i.deductGas(BranchEqCost); err != nil {
			return 0, err
		}
		return 0, i.BranchEq(i.decodeArgsReg2Offset())
	case BranchNe:
		if err := i.deductGas(BranchNotEqCost); err != nil {
			return 0, err
		}
		return 0, i.BranchNe(i.decodeArgsReg2Offset())
	case BranchLtU:
		if err := i.deductGas(BranchLessUnsignedCost); err != nil {
			return 0, err
		}
		return 0, i.BranchLtU(i.decodeArgsReg2Offset())
	case BranchLtS:
		if err := i.deductGas(BranchLessSignedCost); err != nil {
			return 0, err
		}
		return 0, i.BranchLtS(i.decodeArgsReg2Offset())
	case BranchGeU:
		if err := i.deductGas(BranchGreaterOrEqualUnsignedCost); err != nil {
			return 0, err
		}
		return 0, i.BranchGeU(i.decodeArgsReg2Offset())
	case BranchGeS:
		if err := i.deductGas(BranchGreaterOrEqualSignedCost); err != nil {
			return 0, err
		}
		return 0, i.BranchGeS(i.decodeArgsReg2Offset())

	// (eq. A.31 v0.7.0)
	case LoadImmJumpInd:
		if err := i.deductGas(LoadImmAndJumpIndirectCost); err != nil {
			return 0, err
		}
		return 0, i.LoadImmJumpInd(i.decodeArgsReg2Imm2())

	// (eq. A.32 v0.7.0)
	case Add32:
		if err := i.deductGas(Add32Cost); err != nil {
			return 0, err
		}
		i.Add32(i.decodeArgsReg3())
	case Sub32:
		if err := i.deductGas(Sub32Cost); err != nil {
			return 0, err
		}
		i.Sub32(i.decodeArgsReg3())
	case Mul32:
		if err := i.deductGas(Mul32Cost); err != nil {
			return 0, err
		}
		i.Mul32(i.decodeArgsReg3())
	case DivU32:
		if err := i.deductGas(DivUnsigned32Cost); err != nil {
			return 0, err
		}
		i.DivU32(i.decodeArgsReg3())
	case DivS32:
		if err := i.deductGas(DivSigned32Cost); err != nil {
			return 0, err
		}
		i.DivS32(i.decodeArgsReg3())
	case RemU32:
		if err := i.deductGas(RemUnsigned32Cost); err != nil {
			return 0, err
		}
		i.RemU32(i.decodeArgsReg3())
	case RemS32:
		if err := i.deductGas(RemSigned32Cost); err != nil {
			return 0, err
		}
		i.RemS32(i.decodeArgsReg3())
	case ShloL32:
		if err := i.deductGas(ShiftLogicalLeft32Cost); err != nil {
			return 0, err
		}
		i.ShloL32(i.decodeArgsReg3())
	case ShloR32:
		if err := i.deductGas(ShiftLogicalRight32Cost); err != nil {
			return 0, err
		}
		i.ShloR32(i.decodeArgsReg3())
	case SharR32:
		if err := i.deductGas(ShiftArithmeticRight32Cost); err != nil {
			return 0, err
		}
		i.SharR32(i.decodeArgsReg3())
	case Add64:
		if err := i.deductGas(Add64Cost); err != nil {
			return 0, err
		}
		i.Add64(i.decodeArgsReg3())
	case Sub64:
		if err := i.deductGas(Sub64Cost); err != nil {
			return 0, err
		}
		i.Sub64(i.decodeArgsReg3())
	case Mul64:
		if err := i.deductGas(Mul64Cost); err != nil {
			return 0, err
		}
		i.Mul64(i.decodeArgsReg3())
	case DivU64:
		if err := i.deductGas(DivUnsigned64Cost); err != nil {
			return 0, err
		}
		i.DivU64(i.decodeArgsReg3())
	case DivS64:
		if err := i.deductGas(DivSigned64Cost); err != nil {
			return 0, err
		}
		i.DivS64(i.decodeArgsReg3())
	case RemU64:
		if err := i.deductGas(RemUnsigned64Cost); err != nil {
			return 0, err
		}
		i.RemU64(i.decodeArgsReg3())
	case RemS64:
		if err := i.deductGas(RemSigned64Cost); err != nil {
			return 0, err
		}
		i.RemS64(i.decodeArgsReg3())
	case ShloL64:
		if err := i.deductGas(ShiftLogicalLeft64Cost); err != nil {
			return 0, err
		}
		i.ShloL64(i.decodeArgsReg3())
	case ShloR64:
		if err := i.deductGas(ShiftLogicalRight64Cost); err != nil {
			return 0, err
		}
		i.ShloR64(i.decodeArgsReg3())
	case SharR64:
		if err := i.deductGas(ShiftArithmeticRight64Cost); err != nil {
			return 0, err
		}
		i.SharR64(i.decodeArgsReg3())
	case And:
		if err := i.deductGas(AndCost); err != nil {
			return 0, err
		}
		i.And(i.decodeArgsReg3())
	case Xor:
		if err := i.deductGas(XorCost); err != nil {
			return 0, err
		}
		i.Xor(i.decodeArgsReg3())
	case Or:
		if err := i.deductGas(OrCost); err != nil {
			return 0, err
		}
		i.Or(i.decodeArgsReg3())
	case MulUpperSS:
		if err := i.deductGas(MulUpperSignedSignedCost); err != nil {
			return 0, err
		}
		i.MulUpperSS(i.decodeArgsReg3())
	case MulUpperUU:
		if err := i.deductGas(MulUpperUnsignedUnsignedCost); err != nil {
			return 0, err
		}
		i.MulUpperUU(i.decodeArgsReg3())
	case MulUpperSU:
		if err := i.deductGas(MulUpperSignedUnsignedCost); err != nil {
			return 0, err
		}
		i.MulUpperSU(i.decodeArgsReg3())
	case SetLtU:
		if err := i.deductGas(SetLessThanUnsignedCost); err != nil {
			return 0, err
		}
		i.SetLtU(i.decodeArgsReg3())
	case SetLtS:
		if err := i.deductGas(SetLessThanSignedCost); err != nil {
			return 0, err
		}
		i.SetLtS(i.decodeArgsReg3())
	case CmovIz:
		if err := i.deductGas(CmovIfZeroCost); err != nil {
			return 0, err
		}
		i.CmovIz(i.decodeArgsReg3())
	case CmovNz:
		if err := i.deductGas(CmovIfNotZeroCost); err != nil {
			return 0, err
		}
		i.CmovNz(i.decodeArgsReg3())
	case RotL64:
		if err := i.deductGas(RotL64Cost); err != nil {
			return 0, err
		}
		i.RotateLeft64(i.decodeArgsReg3())
	case RotL32:
		if err := i.deductGas(RotL32Cost); err != nil {
			return 0, err
		}
		i.RotateLeft32(i.decodeArgsReg3())
	case RotR64:
		if err := i.deductGas(RotR64Cost); err != nil {
			return 0, err
		}
		i.RotateRight64(i.decodeArgsReg3())
	case RotR32:
		if err := i.deductGas(RotR32Cost); err != nil {
			return 0, err
		}
		i.RotateRight32(i.decodeArgsReg3())
	case AndInv:
		if err := i.deductGas(AndInvCost); err != nil {
			return 0, err
		}
		i.AndInverted(i.decodeArgsReg3())
	case OrInv:
		if err := i.deductGas(OrInvCost); err != nil {
			return 0, err
		}
		i.OrInverted(i.decodeArgsReg3())
	case Xnor:
		if err := i.deductGas(XnorCost); err != nil {
			return 0, err
		}
		i.Xnor(i.decodeArgsReg3())
	case Max:
		if err := i.deductGas(MaxCost); err != nil {
			return 0, err
		}
		i.Max(i.decodeArgsReg3())
	case MaxU:
		if err := i.deductGas(MaxUCost); err != nil {
			return 0, err
		}
		i.MaxUnsigned(i.decodeArgsReg3())
	case Min:
		if err := i.deductGas(MinCost); err != nil {
			return 0, err
		}
		i.Min(i.decodeArgsReg3())
	case MinU:
		if err := i.deductGas(MinUCost); err != nil {
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

func (i *Instance) decodeArgsRegImmExt() (regA Reg, valueX uint64) {
	if instr := i.instructionsCache[i.instructionCounter]; instr != nil {
		return instr.reg[0], instr.val[0]
	}
	// let rA = min(12, ζı+1 mod 16), φ′A ≡ φ′rA
	regA = Reg(min(12, i.code[i.instructionCounter+1]%16))
	// νX ≡ E−1_8(ζı+2⋅⋅⋅+8)
	valueX = jam.DecodeUint64(i.code[i.instructionCounter+2 : i.instructionCounter+10])
	i.instructionsCache[i.instructionCounter] = &instructionCache{reg: [3]Reg{regA}, val: [2]uint64{valueX}}
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

func (i *Instance) decodeArgsRegImm() (regA Reg, valueX uint64) {
	if instr := i.instructionsCache[i.instructionCounter]; instr != nil {
		return instr.reg[0], instr.val[0]
	}
	// let lX = min(4, max(0, ℓ − 1))
	lenX := uint64(min(4, max(0, int(i.skipLen)-1)))
	// let rA = min(12, ζı+1 mod 16), φ′A ≡ φ′rA
	regA = Reg(min(12, i.code[i.instructionCounter+1]%16))

	// νX ≡ X_lX(E−1_lX(ζı+2...+lX))
	valueX = sext(jam.DecodeUint64(i.code[i.instructionCounter+2:i.instructionCounter+2+lenX]), lenX)
	i.instructionsCache[i.instructionCounter] = &instructionCache{reg: [3]Reg{regA}, val: [2]uint64{valueX}}
	return regA, valueX
}

func (i *Instance) decodeArgsRegImm2() (regA Reg, valueX, valueY uint64) {
	if instr := i.instructionsCache[i.instructionCounter]; instr != nil {
		return instr.reg[0], instr.val[0], instr.val[1]
	}
	// let rA = min(12, ζı+1 mod 16), φA ≡ φrA, φ′A ≡ φ′rA
	regA = Reg(min(12, i.code[i.instructionCounter+1]%16))
	// let lX = min(4, ⌊ ζı+1 / 16 ⌋ mod 8)
	lenX := uint64(min(4, (i.code[i.instructionCounter+1]/16)%8))

	// let lY = min(4, max(0, ℓ − lX − 1))
	lenY := uint64(min(4, max(0, int(i.skipLen)-int(lenX)-1)))

	// νX = X_lX (E−1lX (ζı+2⋅⋅⋅+lX))
	valueX = sext(jam.DecodeUint64(i.code[i.instructionCounter+2:i.instructionCounter+2+lenX]), lenX)

	// νY = X_lY(E−1lY (ζı+2+lX ⋅⋅⋅+lY))
	valueY = sext(jam.DecodeUint64(i.code[i.instructionCounter+2+lenX:i.instructionCounter+2+lenX+lenY]), lenY)
	i.instructionsCache[i.instructionCounter] = &instructionCache{reg: [3]Reg{regA}, val: [2]uint64{valueX, valueY}}
	return regA, valueX, valueY
}

func (i *Instance) decodeArgsRegImmOffset() (regA Reg, valueX, valueY uint64) {
	if instr := i.instructionsCache[i.instructionCounter]; instr != nil {
		return instr.reg[0], instr.val[0], instr.val[1]
	}
	// let rA = min(12, ζı+1 mod 16), φA ≡ φrA, φ′A ≡ φ′rA
	regA = Reg(min(12, i.code[i.instructionCounter+1]%16))
	// let lX = min(4, ⌊ ζı+1 / 16 ⌋ mod 8)
	lenX := uint64(min(4, (i.code[i.instructionCounter+1]/16)%8))
	// let lY = min(4, max(0, ℓ − lX − 1))
	lenY := uint64(min(4, max(0, int(i.skipLen)-int(lenX)-1)))

	// νX = X_lX(E−1lX (ζı+2...+lX))
	valueX = sext(jam.DecodeUint64(i.code[i.instructionCounter+2:i.instructionCounter+2+lenX]), lenX)
	// νY = ı + ZlY(E−1lY (ζı+2+lX⋅⋅⋅+lY))
	valueY = uint64(int64(i.instructionCounter) + signed(jam.DecodeUint64(i.code[i.instructionCounter+2+lenX:i.instructionCounter+2+lenX+lenY]), lenY))
	i.instructionsCache[i.instructionCounter] = &instructionCache{reg: [3]Reg{regA}, val: [2]uint64{valueX, valueY}}
	return regA, valueX, valueY
}

func (i *Instance) decodeArgsReg2() (regDst, regA Reg) {
	if instr := i.instructionsCache[i.instructionCounter]; instr != nil {
		return instr.reg[0], instr.reg[1]
	}
	// let rD = min(12, (ζı+1) mod 16) , φD ≡ φrD , φ′D ≡ φ′rD
	regDst = Reg(min(12, i.code[i.instructionCounter+1]%16))

	// let rA = min(12, ⌊ ζı+1 / 16 ⌋) , φA ≡ φrA , φ′A ≡ φ′rA
	regA = Reg(min(12, i.code[i.instructionCounter+1]/16))
	i.instructionsCache[i.instructionCounter] = &instructionCache{reg: [3]Reg{regDst, regA}}
	return regDst, regA
}

func (i *Instance) decodeArgsReg2Imm() (regA, regB Reg, valueX uint64) {
	if instr := i.instructionsCache[i.instructionCounter]; instr != nil {
		return instr.reg[0], instr.reg[1], instr.val[0]
	}
	// let lX = min(4, max(0, ℓ − 1))
	lenX := uint64(min(4, max(0, int(i.skipLen)-1)))
	// let rA = min(12, (ζı+1) mod 16), φA ≡ φrA, φ′A ≡ φ′rA
	regA = Reg(min(12, i.code[i.instructionCounter+1]%16))
	// let rB = min(12, ⌊ ζı+1 / 16 ⌋), φB ≡ φrB, φ′B ≡ φ′rB
	regB = Reg(min(12, i.code[i.instructionCounter+1]/16))

	// νX ≡ X_lX(E−1lX(ζı+2...+lX))
	valueX = sext(jam.DecodeUint64(i.code[i.instructionCounter+2:i.instructionCounter+2+lenX]), lenX)
	i.instructionsCache[i.instructionCounter] = &instructionCache{reg: [3]Reg{regA, regB}, val: [2]uint64{valueX}}
	return regA, regB, valueX
}

func (i *Instance) decodeArgsReg2Offset() (regA, regB Reg, valueX uint64) {
	if instr := i.instructionsCache[i.instructionCounter]; instr != nil {
		return instr.reg[0], instr.reg[1], instr.val[0]
	}
	// let lX = min(4, max(0, ℓ − 1))
	lenX := uint64(min(4, max(0, int(i.skipLen)-1)))
	// let rA = min(12, (ζı+1) mod 16), φA ≡ φrA, φ′A ≡ φ′rA
	regA = Reg(min(12, i.code[i.instructionCounter+1]%16))
	// let rB = min(12, ⌊ ζı+1 / 16 ⌋), φB ≡ φrB, φ′B ≡ φ′rB
	regB = Reg(min(12, i.code[i.instructionCounter+1]/16))

	// νX ≡ ı + Z_lX(E−1lX(ζı+2...+lX))
	valueX = uint64(int64(i.instructionCounter) + signed(jam.DecodeUint64(i.code[i.instructionCounter+2:i.instructionCounter+2+lenX]), lenX))
	i.instructionsCache[i.instructionCounter] = &instructionCache{reg: [3]Reg{regA, regB}, val: [2]uint64{valueX}}
	return regA, regB, valueX
}

func (i *Instance) decodeArgsReg2Imm2() (regA, regB Reg, valueX, valueY uint64) {
	if instr := i.instructionsCache[i.instructionCounter]; instr != nil {
		return instr.reg[0], instr.reg[1], instr.val[0], instr.val[1]
	}
	// let rA = min(12, (ζı+1) mod 16), φA ≡ φrA, φ′A ≡ φ′rA
	regA = Reg(min(12, i.code[i.instructionCounter+1]%16))
	// let rB = min(12, ⌊ ζı+1 / 16 ⌋), φB ≡ φrB, φ′B ≡ φ′rB
	regB = Reg(min(12, i.code[i.instructionCounter+1]/16))
	// let lX = min(4, ζı+2 mod 8)
	lenX := uint64(min(4, i.code[i.instructionCounter+2]%8))
	// let lY = min(4, max(0, ℓ − lX − 2))
	lenY := uint64(min(4, max(0, int(i.skipLen)-int(lenX)-2)))

	// νX = X_lX(E−1lX (ζı+3⋅⋅⋅+lX))
	valueX = jam.DecodeUint64(i.code[i.instructionCounter+3 : i.instructionCounter+3+lenX])
	// vY = X_lY(E−1lY (ζı+3+lX ⋅⋅⋅+lY))
	valueY = sext(jam.DecodeUint64(i.code[i.instructionCounter+3+lenX:i.instructionCounter+3+lenX+lenY]), lenY)

	i.instructionsCache[i.instructionCounter] = &instructionCache{reg: [3]Reg{regA, regB}, val: [2]uint64{valueX, valueY}}
	return regA, regB, valueX, valueY
}

func (i *Instance) decodeArgsReg3() (regDst, regA, regB Reg) {
	if instr := i.instructionsCache[i.instructionCounter]; instr != nil {
		return instr.reg[0], instr.reg[1], instr.reg[2]
	}
	// let rA = min(12, (ζı+1) mod 16), φA ≡ φrA, φ′A ≡ φ′rA
	regA = Reg(min(12, i.code[i.instructionCounter+1]%16))
	// let rB = min(12, ⌊ ζı+1 / 16 ⌋), φB ≡ φrB, φ′B ≡ φ′rB
	regB = Reg(min(12, i.code[i.instructionCounter+1]/16))
	// let rD = min(12, ζı+2), φD ≡ φrD, φ′D ≡ φ′rD
	regDst = Reg(min(12, i.code[i.instructionCounter+2]))

	i.instructionsCache[i.instructionCounter] = &instructionCache{reg: [3]Reg{regDst, regA, regB}}
	return regDst, regA, regB
}
