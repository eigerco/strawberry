package pvm

// step Ψ1(B, B, ⟦NR⟧, NR, NG, ⟦NR⟧13, M) → ({☇, ∎, ▸} ∪ {F,-h} × NR, NR, ZG, ⟦NR⟧13, M) (A.6 v0.7.2)
func (i *Instance) step() (uint64, error) {
	codeLength := uint64(len(i.code))
	// ℓ ≡ skip(ı) (eq. A.20 v0.7.2)
	// precomputed skip length
	i.skipLen = i.program.skip(i.instructionCounter)

	// ζ ≡ c ⌢ [0, 0, ... ] (eq. A.4 v0.7.2)
	// We cannot add infinite items to a slice, but we simulate this by defaulting to trap opcode
	opcode := Trap

	if i.instructionCounter < codeLength {
		opcode = i.unsafeOpcode(i.instructionCounter)
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
		return i.decodeArgsImm(i.instructionCounter, i.skipLen), ErrHostCall

	// (eq. A.22 v0.7.0)
	case LoadImm64:
		if err := i.deductGas(LoadImm64Cost); err != nil {
			return 0, err
		}
		i.LoadImm64(i.decodeArgsRegImmExt(i.instructionCounter, i.skipLen))

	// (eq. A.23 v0.7.0)
	case StoreImmU8:
		if err := i.deductGas(StoreImmU8Cost); err != nil {
			return 0, err
		}
		return 0, i.StoreImmU8(i.decodeArgsImm2(i.instructionCounter, i.skipLen))
	case StoreImmU16:
		if err := i.deductGas(StoreImmU16Cost); err != nil {
			return 0, err
		}
		return 0, i.StoreImmU16(i.decodeArgsImm2(i.instructionCounter, i.skipLen))
	case StoreImmU32:
		if err := i.deductGas(StoreImmU32Cost); err != nil {
			return 0, err
		}
		return 0, i.StoreImmU32(i.decodeArgsImm2(i.instructionCounter, i.skipLen))
	case StoreImmU64:
		if err := i.deductGas(StoreImmU64Cost); err != nil {
			return 0, err
		}
		return 0, i.StoreImmU64(i.decodeArgsImm2(i.instructionCounter, i.skipLen))

	// (eq. A.24 v0.7.0)
	case Jump:
		if err := i.deductGas(JumpCost); err != nil {
			return 0, err
		}
		return 0, i.Jump(i.decodeArgsOffset(i.instructionCounter, i.skipLen))

	// (eq. A.25 v0.7.0)
	case JumpInd:
		if err := i.deductGas(JumpIndirectCost); err != nil {
			return 0, err
		}
		return 0, i.JumpInd(i.decodeArgsRegImm(i.instructionCounter, i.skipLen))
	case LoadImm:
		if err := i.deductGas(LoadImmCost); err != nil {
			return 0, err
		}
		i.LoadImm(i.decodeArgsRegImm(i.instructionCounter, i.skipLen))
	case LoadU8:
		if err := i.deductGas(LoadU8Cost); err != nil {
			return 0, err
		}
		return 0, i.LoadU8(i.decodeArgsRegImm(i.instructionCounter, i.skipLen))
	case LoadI8:
		if err := i.deductGas(LoadI8Cost); err != nil {
			return 0, err
		}
		return 0, i.LoadI8(i.decodeArgsRegImm(i.instructionCounter, i.skipLen))
	case LoadU16:
		if err := i.deductGas(LoadU16Cost); err != nil {
			return 0, err
		}
		return 0, i.LoadU16(i.decodeArgsRegImm(i.instructionCounter, i.skipLen))
	case LoadI16:
		if err := i.deductGas(LoadI16Cost); err != nil {
			return 0, err
		}
		return 0, i.LoadI16(i.decodeArgsRegImm(i.instructionCounter, i.skipLen))
	case LoadU32:
		if err := i.deductGas(LoadU32Cost); err != nil {
			return 0, err
		}
		return 0, i.LoadU32(i.decodeArgsRegImm(i.instructionCounter, i.skipLen))
	case LoadI32:
		if err := i.deductGas(LoadI32Cost); err != nil {
			return 0, err
		}
		return 0, i.LoadI32(i.decodeArgsRegImm(i.instructionCounter, i.skipLen))
	case LoadU64:
		if err := i.deductGas(LoadU64Cost); err != nil {
			return 0, err
		}
		return 0, i.LoadU64(i.decodeArgsRegImm(i.instructionCounter, i.skipLen))
	case StoreU8:
		if err := i.deductGas(StoreU8Cost); err != nil {
			return 0, err
		}
		return 0, i.StoreU8(i.decodeArgsRegImm(i.instructionCounter, i.skipLen))
	case StoreU16:
		if err := i.deductGas(StoreU16Cost); err != nil {
			return 0, err
		}
		return 0, i.StoreU16(i.decodeArgsRegImm(i.instructionCounter, i.skipLen))
	case StoreU32:
		if err := i.deductGas(StoreU32Cost); err != nil {
			return 0, err
		}
		return 0, i.StoreU32(i.decodeArgsRegImm(i.instructionCounter, i.skipLen))
	case StoreU64:
		if err := i.deductGas(StoreU64Cost); err != nil {
			return 0, err
		}
		return 0, i.StoreU64(i.decodeArgsRegImm(i.instructionCounter, i.skipLen))

	// (eq. A.26 v0.7.0)
	case StoreImmIndU8:
		if err := i.deductGas(StoreImmIndirectU8Cost); err != nil {
			return 0, err
		}
		return 0, i.StoreImmIndU8(i.decodeArgsRegImm2(i.instructionCounter, i.skipLen))
	case StoreImmIndU16:
		if err := i.deductGas(StoreImmIndirectU16Cost); err != nil {
			return 0, err
		}
		return 0, i.StoreImmIndU16(i.decodeArgsRegImm2(i.instructionCounter, i.skipLen))
	case StoreImmIndU32:
		if err := i.deductGas(StoreImmIndirectU32Cost); err != nil {
			return 0, err
		}
		return 0, i.StoreImmIndU32(i.decodeArgsRegImm2(i.instructionCounter, i.skipLen))
	case StoreImmIndU64:
		if err := i.deductGas(StoreImmIndirectU64Cost); err != nil {
			return 0, err
		}
		return 0, i.StoreImmIndU64(i.decodeArgsRegImm2(i.instructionCounter, i.skipLen))

	// (eq. A.27 v0.7.0)
	case LoadImmJump:
		if err := i.deductGas(LoadImmAndJumpCost); err != nil {
			return 0, err
		}
		return 0, i.LoadImmJump(i.decodeArgsRegImmOffset(i.instructionCounter, i.skipLen))
	case BranchEqImm:
		if err := i.deductGas(BranchEqImmCost); err != nil {
			return 0, err
		}
		return 0, i.BranchEqImm(i.decodeArgsRegImmOffset(i.instructionCounter, i.skipLen))
	case BranchNeImm:
		if err := i.deductGas(BranchNotEqImmCost); err != nil {
			return 0, err
		}
		return 0, i.BranchNeImm(i.decodeArgsRegImmOffset(i.instructionCounter, i.skipLen))
	case BranchLtUImm:
		if err := i.deductGas(BranchLessUnsignedImmCost); err != nil {
			return 0, err
		}
		return 0, i.BranchLtUImm(i.decodeArgsRegImmOffset(i.instructionCounter, i.skipLen))
	case BranchLeUImm:
		if err := i.deductGas(BranchLessOrEqualUnsignedImmCost); err != nil {
			return 0, err
		}
		return 0, i.BranchLeUImm(i.decodeArgsRegImmOffset(i.instructionCounter, i.skipLen))
	case BranchGeUImm:
		if err := i.deductGas(BranchGreaterOrEqualUnsignedImmCost); err != nil {
			return 0, err
		}
		return 0, i.BranchGeUImm(i.decodeArgsRegImmOffset(i.instructionCounter, i.skipLen))
	case BranchGtUImm:
		if err := i.deductGas(BranchGreaterUnsignedImmCost); err != nil {
			return 0, err
		}
		return 0, i.BranchGtUImm(i.decodeArgsRegImmOffset(i.instructionCounter, i.skipLen))
	case BranchLtSImm:
		if err := i.deductGas(BranchLessSignedImmCost); err != nil {
			return 0, err
		}
		return 0, i.BranchLtSImm(i.decodeArgsRegImmOffset(i.instructionCounter, i.skipLen))
	case BranchLeSImm:
		if err := i.deductGas(BranchLessOrEqualSignedImmCost); err != nil {
			return 0, err
		}
		return 0, i.BranchLeSImm(i.decodeArgsRegImmOffset(i.instructionCounter, i.skipLen))
	case BranchGeSImm:
		if err := i.deductGas(BranchGreaterOrEqualSignedImmCost); err != nil {
			return 0, err
		}
		return 0, i.BranchGeSImm(i.decodeArgsRegImmOffset(i.instructionCounter, i.skipLen))
	case BranchGtSImm:
		if err := i.deductGas(BranchGreaterSignedImmCost); err != nil {
			return 0, err
		}
		return 0, i.BranchGtSImm(i.decodeArgsRegImmOffset(i.instructionCounter, i.skipLen))

	// (eq. A.28 v0.7.0)
	case MoveReg:
		if err := i.deductGas(MoveRegCost); err != nil {
			return 0, err
		}
		i.MoveReg(i.decodeArgsReg2(i.instructionCounter))
	case Sbrk:
		if err := i.deductGas(SbrkCost); err != nil {
			return 0, err
		}
		return 0, i.Sbrk(i.decodeArgsReg2(i.instructionCounter))
	case CountSetBits64:
		if err := i.deductGas(CountSetBits64Cost); err != nil {
			return 0, err
		}
		i.CountSetBits64(i.decodeArgsReg2(i.instructionCounter))
	case CountSetBits32:
		if err := i.deductGas(CountSetBits32Cost); err != nil {
			return 0, err
		}
		i.CountSetBits32(i.decodeArgsReg2(i.instructionCounter))
	case LeadingZeroBits64:
		if err := i.deductGas(LeadingZeroBits64Cost); err != nil {
			return 0, err
		}
		i.LeadingZeroBits64(i.decodeArgsReg2(i.instructionCounter))
	case LeadingZeroBits32:
		if err := i.deductGas(LeadingZeroBits32Cost); err != nil {
			return 0, err
		}
		i.LeadingZeroBits32(i.decodeArgsReg2(i.instructionCounter))
	case TrailingZeroBits64:
		if err := i.deductGas(TrailingZeroBits64Cost); err != nil {
			return 0, err
		}
		i.TrailingZeroBits64(i.decodeArgsReg2(i.instructionCounter))
	case TrailingZeroBits32:
		if err := i.deductGas(TrailingZeroBits32Cost); err != nil {
			return 0, err
		}
		i.TrailingZeroBits32(i.decodeArgsReg2(i.instructionCounter))
	case SignExtend8:
		if err := i.deductGas(SignExtend8Cost); err != nil {
			return 0, err
		}
		i.SignExtend8(i.decodeArgsReg2(i.instructionCounter))
	case SignExtend16:
		if err := i.deductGas(SignExtend16Cost); err != nil {
			return 0, err
		}
		i.SignExtend16(i.decodeArgsReg2(i.instructionCounter))
	case ZeroExtend16:
		if err := i.deductGas(ZeroExtend16Cost); err != nil {
			return 0, err
		}
		i.ZeroExtend16(i.decodeArgsReg2(i.instructionCounter))
	case ReverseBytes:
		if err := i.deductGas(ReverseBytesCost); err != nil {
			return 0, err
		}
		i.ReverseBytes(i.decodeArgsReg2(i.instructionCounter))

	// (eq. A.29 v0.7.0)
	case StoreIndU8:
		if err := i.deductGas(StoreIndirectU8Cost); err != nil {
			return 0, err
		}
		return 0, i.StoreIndU8(i.decodeArgsReg2Imm(i.instructionCounter, i.skipLen))
	case StoreIndU16:
		if err := i.deductGas(StoreIndirectU16Cost); err != nil {
			return 0, err
		}
		return 0, i.StoreIndU16(i.decodeArgsReg2Imm(i.instructionCounter, i.skipLen))
	case StoreIndU32:
		if err := i.deductGas(StoreIndirectU32Cost); err != nil {
			return 0, err
		}
		return 0, i.StoreIndU32(i.decodeArgsReg2Imm(i.instructionCounter, i.skipLen))
	case StoreIndU64:
		if err := i.deductGas(StoreIndirectU64Cost); err != nil {
			return 0, err
		}
		return 0, i.StoreIndU64(i.decodeArgsReg2Imm(i.instructionCounter, i.skipLen))
	case LoadIndU8:
		if err := i.deductGas(LoadIndirectU8Cost); err != nil {
			return 0, err
		}
		return 0, i.LoadIndU8(i.decodeArgsReg2Imm(i.instructionCounter, i.skipLen))
	case LoadIndI8:
		if err := i.deductGas(LoadIndirectI8Cost); err != nil {
			return 0, err
		}
		return 0, i.LoadIndI8(i.decodeArgsReg2Imm(i.instructionCounter, i.skipLen))
	case LoadIndU16:
		if err := i.deductGas(LoadIndirectU16Cost); err != nil {
			return 0, err
		}
		return 0, i.LoadIndU16(i.decodeArgsReg2Imm(i.instructionCounter, i.skipLen))
	case LoadIndI16:
		if err := i.deductGas(LoadIndirectI16Cost); err != nil {
			return 0, err
		}
		return 0, i.LoadIndI16(i.decodeArgsReg2Imm(i.instructionCounter, i.skipLen))
	case LoadIndU32:
		if err := i.deductGas(LoadIndirectU32Cost); err != nil {
			return 0, err
		}
		return 0, i.LoadIndU32(i.decodeArgsReg2Imm(i.instructionCounter, i.skipLen))
	case LoadIndI32:
		if err := i.deductGas(LoadIndirectI32Cost); err != nil {
			return 0, err
		}
		return 0, i.LoadIndI32(i.decodeArgsReg2Imm(i.instructionCounter, i.skipLen))
	case LoadIndU64:
		if err := i.deductGas(LoadIndirectU64Cost); err != nil {
			return 0, err
		}
		return 0, i.LoadIndU64(i.decodeArgsReg2Imm(i.instructionCounter, i.skipLen))
	case AddImm32:
		if err := i.deductGas(AddImm32Cost); err != nil {
			return 0, err
		}
		i.AddImm32(i.decodeArgsReg2Imm(i.instructionCounter, i.skipLen))
	case AndImm:
		if err := i.deductGas(AndImmCost); err != nil {
			return 0, err
		}
		i.AndImm(i.decodeArgsReg2Imm(i.instructionCounter, i.skipLen))
	case XorImm:
		if err := i.deductGas(XorImmCost); err != nil {
			return 0, err
		}
		i.XorImm(i.decodeArgsReg2Imm(i.instructionCounter, i.skipLen))
	case OrImm:
		if err := i.deductGas(OrImmCost); err != nil {
			return 0, err
		}
		i.OrImm(i.decodeArgsReg2Imm(i.instructionCounter, i.skipLen))
	case MulImm32:
		if err := i.deductGas(MulImm32Cost); err != nil {
			return 0, err
		}
		i.MulImm32(i.decodeArgsReg2Imm(i.instructionCounter, i.skipLen))
	case SetLtUImm:
		if err := i.deductGas(SetLessThanUnsignedImmCost); err != nil {
			return 0, err
		}
		i.SetLtUImm(i.decodeArgsReg2Imm(i.instructionCounter, i.skipLen))
	case SetLtSImm:
		if err := i.deductGas(SetLessThanSignedImmCost); err != nil {
			return 0, err
		}
		i.SetLtSImm(i.decodeArgsReg2Imm(i.instructionCounter, i.skipLen))
	case ShloLImm32:
		if err := i.deductGas(ShiftLogicalLeftImm32Cost); err != nil {
			return 0, err
		}
		i.ShloLImm32(i.decodeArgsReg2Imm(i.instructionCounter, i.skipLen))
	case ShloRImm32:
		if err := i.deductGas(ShiftLogicalRightImm32Cost); err != nil {
			return 0, err
		}
		i.ShloRImm32(i.decodeArgsReg2Imm(i.instructionCounter, i.skipLen))
	case SharRImm32:
		if err := i.deductGas(ShiftArithmeticRightImm32Cost); err != nil {
			return 0, err
		}
		i.SharRImm32(i.decodeArgsReg2Imm(i.instructionCounter, i.skipLen))
	case NegAddImm32:
		if err := i.deductGas(NegateAndAddImm32Cost); err != nil {
			return 0, err
		}
		i.NegAddImm32(i.decodeArgsReg2Imm(i.instructionCounter, i.skipLen))
	case SetGtUImm:
		if err := i.deductGas(SetGreaterThanUnsignedImmCost); err != nil {
			return 0, err
		}
		i.SetGtUImm(i.decodeArgsReg2Imm(i.instructionCounter, i.skipLen))
	case SetGtSImm:
		if err := i.deductGas(SetGreaterThanSignedImmCost); err != nil {
			return 0, err
		}
		i.SetGtSImm(i.decodeArgsReg2Imm(i.instructionCounter, i.skipLen))
	case ShloLImmAlt32:
		if err := i.deductGas(ShiftLogicalLeftImmAlt32Cost); err != nil {
			return 0, err
		}
		i.ShloLImmAlt32(i.decodeArgsReg2Imm(i.instructionCounter, i.skipLen))
	case ShloRImmAlt32:
		if err := i.deductGas(ShiftArithmeticRightImmAlt32Cost); err != nil {
			return 0, err
		}
		i.SharRImmAlt32(i.decodeArgsReg2Imm(i.instructionCounter, i.skipLen))
	case SharRImmAlt32:
		if err := i.deductGas(ShiftLogicalRightImmAlt32Cost); err != nil {
			return 0, err
		}
		i.ShloRImmAlt32(i.decodeArgsReg2Imm(i.instructionCounter, i.skipLen))
	case CmovIzImm:
		if err := i.deductGas(CmovIfZeroImmCost); err != nil {
			return 0, err
		}
		i.CmovIzImm(i.decodeArgsReg2Imm(i.instructionCounter, i.skipLen))
	case CmovNzImm:
		if err := i.deductGas(CmovIfNotZeroImmCost); err != nil {
			return 0, err
		}
		i.CmovNzImm(i.decodeArgsReg2Imm(i.instructionCounter, i.skipLen))
	case AddImm64:
		if err := i.deductGas(AddImm64Cost); err != nil {
			return 0, err
		}
		i.AddImm64(i.decodeArgsReg2Imm(i.instructionCounter, i.skipLen))
	case MulImm64:
		if err := i.deductGas(MulImm64Cost); err != nil {
			return 0, err
		}
		i.MulImm64(i.decodeArgsReg2Imm(i.instructionCounter, i.skipLen))
	case ShloLImm64:
		if err := i.deductGas(ShiftLogicalLeftImm64Cost); err != nil {
			return 0, err
		}
		i.ShloLImm64(i.decodeArgsReg2Imm(i.instructionCounter, i.skipLen))
	case ShloRImm64:
		if err := i.deductGas(ShiftLogicalRightImm64Cost); err != nil {
			return 0, err
		}
		i.ShloRImm64(i.decodeArgsReg2Imm(i.instructionCounter, i.skipLen))
	case SharRImm64:
		if err := i.deductGas(ShiftArithmeticRightImm64Cost); err != nil {
			return 0, err
		}
		i.SharRImm64(i.decodeArgsReg2Imm(i.instructionCounter, i.skipLen))
	case NegAddImm64:
		if err := i.deductGas(NegateAndAddImm64Cost); err != nil {
			return 0, err
		}
		i.NegAddImm64(i.decodeArgsReg2Imm(i.instructionCounter, i.skipLen))
	case ShloLImmAlt64:
		if err := i.deductGas(ShiftLogicalLeftImmAlt64Cost); err != nil {
			return 0, err
		}
		i.ShloLImmAlt64(i.decodeArgsReg2Imm(i.instructionCounter, i.skipLen))
	case ShloRImmAlt64:
		if err := i.deductGas(ShiftLogicalRightImmAlt64Cost); err != nil {
			return 0, err
		}
		i.ShloRImmAlt64(i.decodeArgsReg2Imm(i.instructionCounter, i.skipLen))
	case SharRImmAlt64:
		if err := i.deductGas(ShiftArithmeticRightImmAlt64Cost); err != nil {
			return 0, err
		}
		i.SharRImmAlt64(i.decodeArgsReg2Imm(i.instructionCounter, i.skipLen))
	case RotR64Imm:
		if err := i.deductGas(RotR64ImmCost); err != nil {
			return 0, err
		}
		i.RotateRight64Imm(i.decodeArgsReg2Imm(i.instructionCounter, i.skipLen))
	case RotR64ImmAlt:
		if err := i.deductGas(RotR64ImmAltCost); err != nil {
			return 0, err
		}
		i.RotateRight64ImmAlt(i.decodeArgsReg2Imm(i.instructionCounter, i.skipLen))
	case RotR32Imm:
		if err := i.deductGas(RotR32ImmCost); err != nil {
			return 0, err
		}
		i.RotateRight32Imm(i.decodeArgsReg2Imm(i.instructionCounter, i.skipLen))
	case RotR32ImmAlt:
		if err := i.deductGas(RotR32ImmAltCost); err != nil {
			return 0, err
		}
		i.RotateRight32ImmAlt(i.decodeArgsReg2Imm(i.instructionCounter, i.skipLen))

	// (eq. A.30 v0.7.0)
	case BranchEq:
		if err := i.deductGas(BranchEqCost); err != nil {
			return 0, err
		}
		return 0, i.BranchEq(i.decodeArgsReg2Offset(i.instructionCounter, i.skipLen))
	case BranchNe:
		if err := i.deductGas(BranchNotEqCost); err != nil {
			return 0, err
		}
		return 0, i.BranchNe(i.decodeArgsReg2Offset(i.instructionCounter, i.skipLen))
	case BranchLtU:
		if err := i.deductGas(BranchLessUnsignedCost); err != nil {
			return 0, err
		}
		return 0, i.BranchLtU(i.decodeArgsReg2Offset(i.instructionCounter, i.skipLen))
	case BranchLtS:
		if err := i.deductGas(BranchLessSignedCost); err != nil {
			return 0, err
		}
		return 0, i.BranchLtS(i.decodeArgsReg2Offset(i.instructionCounter, i.skipLen))
	case BranchGeU:
		if err := i.deductGas(BranchGreaterOrEqualUnsignedCost); err != nil {
			return 0, err
		}
		return 0, i.BranchGeU(i.decodeArgsReg2Offset(i.instructionCounter, i.skipLen))
	case BranchGeS:
		if err := i.deductGas(BranchGreaterOrEqualSignedCost); err != nil {
			return 0, err
		}
		return 0, i.BranchGeS(i.decodeArgsReg2Offset(i.instructionCounter, i.skipLen))

	// (eq. A.31 v0.7.0)
	case LoadImmJumpInd:
		if err := i.deductGas(LoadImmAndJumpIndirectCost); err != nil {
			return 0, err
		}
		return 0, i.LoadImmJumpInd(i.decodeArgsReg2Imm2(i.instructionCounter, i.skipLen))

	// (eq. A.32 v0.7.0)
	case Add32:
		if err := i.deductGas(Add32Cost); err != nil {
			return 0, err
		}
		i.Add32(i.decodeArgsReg3(i.instructionCounter))
	case Sub32:
		if err := i.deductGas(Sub32Cost); err != nil {
			return 0, err
		}
		i.Sub32(i.decodeArgsReg3(i.instructionCounter))
	case Mul32:
		if err := i.deductGas(Mul32Cost); err != nil {
			return 0, err
		}
		i.Mul32(i.decodeArgsReg3(i.instructionCounter))
	case DivU32:
		if err := i.deductGas(DivUnsigned32Cost); err != nil {
			return 0, err
		}
		i.DivU32(i.decodeArgsReg3(i.instructionCounter))
	case DivS32:
		if err := i.deductGas(DivSigned32Cost); err != nil {
			return 0, err
		}
		i.DivS32(i.decodeArgsReg3(i.instructionCounter))
	case RemU32:
		if err := i.deductGas(RemUnsigned32Cost); err != nil {
			return 0, err
		}
		i.RemU32(i.decodeArgsReg3(i.instructionCounter))
	case RemS32:
		if err := i.deductGas(RemSigned32Cost); err != nil {
			return 0, err
		}
		i.RemS32(i.decodeArgsReg3(i.instructionCounter))
	case ShloL32:
		if err := i.deductGas(ShiftLogicalLeft32Cost); err != nil {
			return 0, err
		}
		i.ShloL32(i.decodeArgsReg3(i.instructionCounter))
	case ShloR32:
		if err := i.deductGas(ShiftLogicalRight32Cost); err != nil {
			return 0, err
		}
		i.ShloR32(i.decodeArgsReg3(i.instructionCounter))
	case SharR32:
		if err := i.deductGas(ShiftArithmeticRight32Cost); err != nil {
			return 0, err
		}
		i.SharR32(i.decodeArgsReg3(i.instructionCounter))
	case Add64:
		if err := i.deductGas(Add64Cost); err != nil {
			return 0, err
		}
		i.Add64(i.decodeArgsReg3(i.instructionCounter))
	case Sub64:
		if err := i.deductGas(Sub64Cost); err != nil {
			return 0, err
		}
		i.Sub64(i.decodeArgsReg3(i.instructionCounter))
	case Mul64:
		if err := i.deductGas(Mul64Cost); err != nil {
			return 0, err
		}
		i.Mul64(i.decodeArgsReg3(i.instructionCounter))
	case DivU64:
		if err := i.deductGas(DivUnsigned64Cost); err != nil {
			return 0, err
		}
		i.DivU64(i.decodeArgsReg3(i.instructionCounter))
	case DivS64:
		if err := i.deductGas(DivSigned64Cost); err != nil {
			return 0, err
		}
		i.DivS64(i.decodeArgsReg3(i.instructionCounter))
	case RemU64:
		if err := i.deductGas(RemUnsigned64Cost); err != nil {
			return 0, err
		}
		i.RemU64(i.decodeArgsReg3(i.instructionCounter))
	case RemS64:
		if err := i.deductGas(RemSigned64Cost); err != nil {
			return 0, err
		}
		i.RemS64(i.decodeArgsReg3(i.instructionCounter))
	case ShloL64:
		if err := i.deductGas(ShiftLogicalLeft64Cost); err != nil {
			return 0, err
		}
		i.ShloL64(i.decodeArgsReg3(i.instructionCounter))
	case ShloR64:
		if err := i.deductGas(ShiftLogicalRight64Cost); err != nil {
			return 0, err
		}
		i.ShloR64(i.decodeArgsReg3(i.instructionCounter))
	case SharR64:
		if err := i.deductGas(ShiftArithmeticRight64Cost); err != nil {
			return 0, err
		}
		i.SharR64(i.decodeArgsReg3(i.instructionCounter))
	case And:
		if err := i.deductGas(AndCost); err != nil {
			return 0, err
		}
		i.And(i.decodeArgsReg3(i.instructionCounter))
	case Xor:
		if err := i.deductGas(XorCost); err != nil {
			return 0, err
		}
		i.Xor(i.decodeArgsReg3(i.instructionCounter))
	case Or:
		if err := i.deductGas(OrCost); err != nil {
			return 0, err
		}
		i.Or(i.decodeArgsReg3(i.instructionCounter))
	case MulUpperSS:
		if err := i.deductGas(MulUpperSignedSignedCost); err != nil {
			return 0, err
		}
		i.MulUpperSS(i.decodeArgsReg3(i.instructionCounter))
	case MulUpperUU:
		if err := i.deductGas(MulUpperUnsignedUnsignedCost); err != nil {
			return 0, err
		}
		i.MulUpperUU(i.decodeArgsReg3(i.instructionCounter))
	case MulUpperSU:
		if err := i.deductGas(MulUpperSignedUnsignedCost); err != nil {
			return 0, err
		}
		i.MulUpperSU(i.decodeArgsReg3(i.instructionCounter))
	case SetLtU:
		if err := i.deductGas(SetLessThanUnsignedCost); err != nil {
			return 0, err
		}
		i.SetLtU(i.decodeArgsReg3(i.instructionCounter))
	case SetLtS:
		if err := i.deductGas(SetLessThanSignedCost); err != nil {
			return 0, err
		}
		i.SetLtS(i.decodeArgsReg3(i.instructionCounter))
	case CmovIz:
		if err := i.deductGas(CmovIfZeroCost); err != nil {
			return 0, err
		}
		i.CmovIz(i.decodeArgsReg3(i.instructionCounter))
	case CmovNz:
		if err := i.deductGas(CmovIfNotZeroCost); err != nil {
			return 0, err
		}
		i.CmovNz(i.decodeArgsReg3(i.instructionCounter))
	case RotL64:
		if err := i.deductGas(RotL64Cost); err != nil {
			return 0, err
		}
		i.RotateLeft64(i.decodeArgsReg3(i.instructionCounter))
	case RotL32:
		if err := i.deductGas(RotL32Cost); err != nil {
			return 0, err
		}
		i.RotateLeft32(i.decodeArgsReg3(i.instructionCounter))
	case RotR64:
		if err := i.deductGas(RotR64Cost); err != nil {
			return 0, err
		}
		i.RotateRight64(i.decodeArgsReg3(i.instructionCounter))
	case RotR32:
		if err := i.deductGas(RotR32Cost); err != nil {
			return 0, err
		}
		i.RotateRight32(i.decodeArgsReg3(i.instructionCounter))
	case AndInv:
		if err := i.deductGas(AndInvCost); err != nil {
			return 0, err
		}
		i.AndInverted(i.decodeArgsReg3(i.instructionCounter))
	case OrInv:
		if err := i.deductGas(OrInvCost); err != nil {
			return 0, err
		}
		i.OrInverted(i.decodeArgsReg3(i.instructionCounter))
	case Xnor:
		if err := i.deductGas(XnorCost); err != nil {
			return 0, err
		}
		i.Xnor(i.decodeArgsReg3(i.instructionCounter))
	case Max:
		if err := i.deductGas(MaxCost); err != nil {
			return 0, err
		}
		i.Max(i.decodeArgsReg3(i.instructionCounter))
	case MaxU:
		if err := i.deductGas(MaxUCost); err != nil {
			return 0, err
		}
		i.MaxUnsigned(i.decodeArgsReg3(i.instructionCounter))
	case Min:
		if err := i.deductGas(MinCost); err != nil {
			return 0, err
		}
		i.Min(i.decodeArgsReg3(i.instructionCounter))
	case MinU:
		if err := i.deductGas(MinUCost); err != nil {
			return 0, err
		}
		i.MinUnsigned(i.decodeArgsReg3(i.instructionCounter))
	default:
		// c_n if kn = 1 ∧ cn ∈ U otherwise 0 (eq. A.19 v0.7.2)
		if err := i.deductGas(TrapCost); err != nil {
			return 0, err
		}
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
