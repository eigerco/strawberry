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

	// Eq. A.8
	//				   ⎧ (▸,ϱ,⊺) 				if ˜ϱ = ⊺
	// (˜ε, ϱ', ˜ϱ′) = ⎨ (▸,ϱ − ϱ∆(c,k,L(ı)),⊺) if ϱ ≥ ϱ∆(ı)
	// 				   ⎩ (∞,ϱ, F) 				otherwise
	initialBlockStart := i.basicBlockStart(i.instructionCounter)
	initialInstructionCounter := i.instructionCounter
	if !i.gasChange {
		basicBlockCost := i.gasCostsMap[initialBlockStart]
		if i.gasRemaining >= basicBlockCost {
			i.gasRemaining -= basicBlockCost
		} else {
			return 0, ErrOutOfGas
		}
	}

	switch opcode {
	case Trap:
		return 0, i.Trap()
	case Fallthrough:
		i.Fallthrough()
	case Unlikely:
		i.Fallthrough()
	// (eq. A.21 v0.7.0)
	case Ecalli:
		// ε = ħ × νX
		return i.decodeArgsImm(i.instructionCounter, i.skipLen), ErrHostCall

	// (eq. A.22 v0.7.0)
	case LoadImm64:
		i.LoadImm64(i.decodeArgsRegImmExt(i.instructionCounter))

	// (eq. A.23 v0.7.0)
	case StoreImmU8:
		return 0, i.StoreImmU8(i.decodeArgsImm2(i.instructionCounter, i.skipLen))
	case StoreImmU16:
		return 0, i.StoreImmU16(i.decodeArgsImm2(i.instructionCounter, i.skipLen))
	case StoreImmU32:
		return 0, i.StoreImmU32(i.decodeArgsImm2(i.instructionCounter, i.skipLen))
	case StoreImmU64:
		return 0, i.StoreImmU64(i.decodeArgsImm2(i.instructionCounter, i.skipLen))

	// (eq. A.24 v0.7.0)
	case Jump:
		return 0, i.Jump(i.decodeArgsOffset(i.instructionCounter, i.skipLen))

	// (eq. A.25 v0.7.0)
	case JumpInd:
		return 0, i.JumpInd(i.decodeArgsRegImm(i.instructionCounter, i.skipLen))
	case LoadImm:
		i.LoadImm(i.decodeArgsRegImm(i.instructionCounter, i.skipLen))
	case LoadU8:
		return 0, i.LoadU8(i.decodeArgsRegImm(i.instructionCounter, i.skipLen))
	case LoadI8:
		return 0, i.LoadI8(i.decodeArgsRegImm(i.instructionCounter, i.skipLen))
	case LoadU16:
		return 0, i.LoadU16(i.decodeArgsRegImm(i.instructionCounter, i.skipLen))
	case LoadI16:
		return 0, i.LoadI16(i.decodeArgsRegImm(i.instructionCounter, i.skipLen))
	case LoadU32:
		return 0, i.LoadU32(i.decodeArgsRegImm(i.instructionCounter, i.skipLen))
	case LoadI32:
		return 0, i.LoadI32(i.decodeArgsRegImm(i.instructionCounter, i.skipLen))
	case LoadU64:
		return 0, i.LoadU64(i.decodeArgsRegImm(i.instructionCounter, i.skipLen))
	case StoreU8:
		return 0, i.StoreU8(i.decodeArgsRegImm(i.instructionCounter, i.skipLen))
	case StoreU16:
		return 0, i.StoreU16(i.decodeArgsRegImm(i.instructionCounter, i.skipLen))
	case StoreU32:
		return 0, i.StoreU32(i.decodeArgsRegImm(i.instructionCounter, i.skipLen))
	case StoreU64:
		return 0, i.StoreU64(i.decodeArgsRegImm(i.instructionCounter, i.skipLen))

	// (eq. A.26 v0.7.0)
	case StoreImmIndU8:
		return 0, i.StoreImmIndU8(i.decodeArgsRegImm2(i.instructionCounter, i.skipLen))
	case StoreImmIndU16:
		return 0, i.StoreImmIndU16(i.decodeArgsRegImm2(i.instructionCounter, i.skipLen))
	case StoreImmIndU32:
		return 0, i.StoreImmIndU32(i.decodeArgsRegImm2(i.instructionCounter, i.skipLen))
	case StoreImmIndU64:
		return 0, i.StoreImmIndU64(i.decodeArgsRegImm2(i.instructionCounter, i.skipLen))

	// (eq. A.27 v0.7.0)
	case LoadImmJump:
		return 0, i.LoadImmJump(i.decodeArgsRegImmOffset(i.instructionCounter, i.skipLen))
	case BranchEqImm:
		return 0, i.BranchEqImm(i.decodeArgsRegImmOffset(i.instructionCounter, i.skipLen))
	case BranchNeImm:
		return 0, i.BranchNeImm(i.decodeArgsRegImmOffset(i.instructionCounter, i.skipLen))
	case BranchLtUImm:
		return 0, i.BranchLtUImm(i.decodeArgsRegImmOffset(i.instructionCounter, i.skipLen))
	case BranchLeUImm:
		return 0, i.BranchLeUImm(i.decodeArgsRegImmOffset(i.instructionCounter, i.skipLen))
	case BranchGeUImm:
		return 0, i.BranchGeUImm(i.decodeArgsRegImmOffset(i.instructionCounter, i.skipLen))
	case BranchGtUImm:
		return 0, i.BranchGtUImm(i.decodeArgsRegImmOffset(i.instructionCounter, i.skipLen))
	case BranchLtSImm:
		return 0, i.BranchLtSImm(i.decodeArgsRegImmOffset(i.instructionCounter, i.skipLen))
	case BranchLeSImm:
		return 0, i.BranchLeSImm(i.decodeArgsRegImmOffset(i.instructionCounter, i.skipLen))
	case BranchGeSImm:
		return 0, i.BranchGeSImm(i.decodeArgsRegImmOffset(i.instructionCounter, i.skipLen))
	case BranchGtSImm:
		return 0, i.BranchGtSImm(i.decodeArgsRegImmOffset(i.instructionCounter, i.skipLen))

	// (eq. A.28 v0.7.0)
	case MoveReg:
		i.MoveReg(i.decodeArgsReg2(i.instructionCounter))
	case CountSetBits64:
		i.CountSetBits64(i.decodeArgsReg2(i.instructionCounter))
	case CountSetBits32:
		i.CountSetBits32(i.decodeArgsReg2(i.instructionCounter))
	case LeadingZeroBits64:
		i.LeadingZeroBits64(i.decodeArgsReg2(i.instructionCounter))
	case LeadingZeroBits32:
		i.LeadingZeroBits32(i.decodeArgsReg2(i.instructionCounter))
	case TrailingZeroBits64:
		i.TrailingZeroBits64(i.decodeArgsReg2(i.instructionCounter))
	case TrailingZeroBits32:
		i.TrailingZeroBits32(i.decodeArgsReg2(i.instructionCounter))
	case SignExtend8:
		i.SignExtend8(i.decodeArgsReg2(i.instructionCounter))
	case SignExtend16:
		i.SignExtend16(i.decodeArgsReg2(i.instructionCounter))
	case ZeroExtend16:
		i.ZeroExtend16(i.decodeArgsReg2(i.instructionCounter))
	case ReverseBytes:
		i.ReverseBytes(i.decodeArgsReg2(i.instructionCounter))

	// (eq. A.29 v0.7.0)
	case StoreIndU8:
		return 0, i.StoreIndU8(i.decodeArgsReg2Imm(i.instructionCounter, i.skipLen))
	case StoreIndU16:
		return 0, i.StoreIndU16(i.decodeArgsReg2Imm(i.instructionCounter, i.skipLen))
	case StoreIndU32:
		return 0, i.StoreIndU32(i.decodeArgsReg2Imm(i.instructionCounter, i.skipLen))
	case StoreIndU64:
		return 0, i.StoreIndU64(i.decodeArgsReg2Imm(i.instructionCounter, i.skipLen))
	case LoadIndU8:
		return 0, i.LoadIndU8(i.decodeArgsReg2Imm(i.instructionCounter, i.skipLen))
	case LoadIndI8:
		return 0, i.LoadIndI8(i.decodeArgsReg2Imm(i.instructionCounter, i.skipLen))
	case LoadIndU16:
		return 0, i.LoadIndU16(i.decodeArgsReg2Imm(i.instructionCounter, i.skipLen))
	case LoadIndI16:
		return 0, i.LoadIndI16(i.decodeArgsReg2Imm(i.instructionCounter, i.skipLen))
	case LoadIndU32:
		return 0, i.LoadIndU32(i.decodeArgsReg2Imm(i.instructionCounter, i.skipLen))
	case LoadIndI32:
		return 0, i.LoadIndI32(i.decodeArgsReg2Imm(i.instructionCounter, i.skipLen))
	case LoadIndU64:
		return 0, i.LoadIndU64(i.decodeArgsReg2Imm(i.instructionCounter, i.skipLen))
	case AddImm32:
		i.AddImm32(i.decodeArgsReg2Imm(i.instructionCounter, i.skipLen))
	case AndImm:
		i.AndImm(i.decodeArgsReg2Imm(i.instructionCounter, i.skipLen))
	case XorImm:
		i.XorImm(i.decodeArgsReg2Imm(i.instructionCounter, i.skipLen))
	case OrImm:
		i.OrImm(i.decodeArgsReg2Imm(i.instructionCounter, i.skipLen))
	case MulImm32:
		i.MulImm32(i.decodeArgsReg2Imm(i.instructionCounter, i.skipLen))
	case SetLtUImm:
		i.SetLtUImm(i.decodeArgsReg2Imm(i.instructionCounter, i.skipLen))
	case SetLtSImm:
		i.SetLtSImm(i.decodeArgsReg2Imm(i.instructionCounter, i.skipLen))
	case ShloLImm32:
		i.ShloLImm32(i.decodeArgsReg2Imm(i.instructionCounter, i.skipLen))
	case ShloRImm32:
		i.ShloRImm32(i.decodeArgsReg2Imm(i.instructionCounter, i.skipLen))
	case SharRImm32:
		i.SharRImm32(i.decodeArgsReg2Imm(i.instructionCounter, i.skipLen))
	case NegAddImm32:
		i.NegAddImm32(i.decodeArgsReg2Imm(i.instructionCounter, i.skipLen))
	case SetGtUImm:
		i.SetGtUImm(i.decodeArgsReg2Imm(i.instructionCounter, i.skipLen))
	case SetGtSImm:
		i.SetGtSImm(i.decodeArgsReg2Imm(i.instructionCounter, i.skipLen))
	case ShloLImmAlt32:
		i.ShloLImmAlt32(i.decodeArgsReg2Imm(i.instructionCounter, i.skipLen))
	case ShloRImmAlt32:
		i.SharRImmAlt32(i.decodeArgsReg2Imm(i.instructionCounter, i.skipLen))
	case SharRImmAlt32:
		i.ShloRImmAlt32(i.decodeArgsReg2Imm(i.instructionCounter, i.skipLen))
	case CmovIzImm:
		i.CmovIzImm(i.decodeArgsReg2Imm(i.instructionCounter, i.skipLen))
	case CmovNzImm:
		i.CmovNzImm(i.decodeArgsReg2Imm(i.instructionCounter, i.skipLen))
	case AddImm64:
		i.AddImm64(i.decodeArgsReg2Imm(i.instructionCounter, i.skipLen))
	case MulImm64:
		i.MulImm64(i.decodeArgsReg2Imm(i.instructionCounter, i.skipLen))
	case ShloLImm64:
		i.ShloLImm64(i.decodeArgsReg2Imm(i.instructionCounter, i.skipLen))
	case ShloRImm64:
		i.ShloRImm64(i.decodeArgsReg2Imm(i.instructionCounter, i.skipLen))
	case SharRImm64:
		i.SharRImm64(i.decodeArgsReg2Imm(i.instructionCounter, i.skipLen))
	case NegAddImm64:
		i.NegAddImm64(i.decodeArgsReg2Imm(i.instructionCounter, i.skipLen))
	case ShloLImmAlt64:
		i.ShloLImmAlt64(i.decodeArgsReg2Imm(i.instructionCounter, i.skipLen))
	case ShloRImmAlt64:
		i.ShloRImmAlt64(i.decodeArgsReg2Imm(i.instructionCounter, i.skipLen))
	case SharRImmAlt64:
		i.SharRImmAlt64(i.decodeArgsReg2Imm(i.instructionCounter, i.skipLen))
	case RotR64Imm:
		i.RotateRight64Imm(i.decodeArgsReg2Imm(i.instructionCounter, i.skipLen))
	case RotR64ImmAlt:
		i.RotateRight64ImmAlt(i.decodeArgsReg2Imm(i.instructionCounter, i.skipLen))
	case RotR32Imm:
		i.RotateRight32Imm(i.decodeArgsReg2Imm(i.instructionCounter, i.skipLen))
	case RotR32ImmAlt:
		i.RotateRight32ImmAlt(i.decodeArgsReg2Imm(i.instructionCounter, i.skipLen))

	// (eq. A.30 v0.7.0)
	case BranchEq:
		return 0, i.BranchEq(i.decodeArgsReg2Offset(i.instructionCounter, i.skipLen))
	case BranchNe:
		return 0, i.BranchNe(i.decodeArgsReg2Offset(i.instructionCounter, i.skipLen))
	case BranchLtU:
		return 0, i.BranchLtU(i.decodeArgsReg2Offset(i.instructionCounter, i.skipLen))
	case BranchLtS:
		return 0, i.BranchLtS(i.decodeArgsReg2Offset(i.instructionCounter, i.skipLen))
	case BranchGeU:
		return 0, i.BranchGeU(i.decodeArgsReg2Offset(i.instructionCounter, i.skipLen))
	case BranchGeS:
		return 0, i.BranchGeS(i.decodeArgsReg2Offset(i.instructionCounter, i.skipLen))

	// (eq. A.31 v0.7.0)
	case LoadImmJumpInd:
		return 0, i.LoadImmJumpInd(i.decodeArgsReg2Imm2(i.instructionCounter, i.skipLen))

	// (eq. A.32 v0.7.0)
	case Add32:
		i.Add32(i.decodeArgsReg3(i.instructionCounter))
	case Sub32:
		i.Sub32(i.decodeArgsReg3(i.instructionCounter))
	case Mul32:
		i.Mul32(i.decodeArgsReg3(i.instructionCounter))
	case DivU32:
		i.DivU32(i.decodeArgsReg3(i.instructionCounter))
	case DivS32:
		i.DivS32(i.decodeArgsReg3(i.instructionCounter))
	case RemU32:
		i.RemU32(i.decodeArgsReg3(i.instructionCounter))
	case RemS32:
		i.RemS32(i.decodeArgsReg3(i.instructionCounter))
	case ShloL32:
		i.ShloL32(i.decodeArgsReg3(i.instructionCounter))
	case ShloR32:
		i.ShloR32(i.decodeArgsReg3(i.instructionCounter))
	case SharR32:
		i.SharR32(i.decodeArgsReg3(i.instructionCounter))
	case Add64:
		i.Add64(i.decodeArgsReg3(i.instructionCounter))
	case Sub64:
		i.Sub64(i.decodeArgsReg3(i.instructionCounter))
	case Mul64:
		i.Mul64(i.decodeArgsReg3(i.instructionCounter))
	case DivU64:
		i.DivU64(i.decodeArgsReg3(i.instructionCounter))
	case DivS64:
		i.DivS64(i.decodeArgsReg3(i.instructionCounter))
	case RemU64:
		i.RemU64(i.decodeArgsReg3(i.instructionCounter))
	case RemS64:
		i.RemS64(i.decodeArgsReg3(i.instructionCounter))
	case ShloL64:
		i.ShloL64(i.decodeArgsReg3(i.instructionCounter))
	case ShloR64:
		i.ShloR64(i.decodeArgsReg3(i.instructionCounter))
	case SharR64:
		i.SharR64(i.decodeArgsReg3(i.instructionCounter))
	case And:
		i.And(i.decodeArgsReg3(i.instructionCounter))
	case Xor:
		i.Xor(i.decodeArgsReg3(i.instructionCounter))
	case Or:
		i.Or(i.decodeArgsReg3(i.instructionCounter))
	case MulUpperSS:
		i.MulUpperSS(i.decodeArgsReg3(i.instructionCounter))
	case MulUpperUU:
		i.MulUpperUU(i.decodeArgsReg3(i.instructionCounter))
	case MulUpperSU:
		i.MulUpperSU(i.decodeArgsReg3(i.instructionCounter))
	case SetLtU:
		i.SetLtU(i.decodeArgsReg3(i.instructionCounter))
	case SetLtS:
		i.SetLtS(i.decodeArgsReg3(i.instructionCounter))
	case CmovIz:
		i.CmovIz(i.decodeArgsReg3(i.instructionCounter))
	case CmovNz:
		i.CmovNz(i.decodeArgsReg3(i.instructionCounter))
	case RotL64:
		i.RotateLeft64(i.decodeArgsReg3(i.instructionCounter))
	case RotL32:
		i.RotateLeft32(i.decodeArgsReg3(i.instructionCounter))
	case RotR64:
		i.RotateRight64(i.decodeArgsReg3(i.instructionCounter))
	case RotR32:
		i.RotateRight32(i.decodeArgsReg3(i.instructionCounter))
	case AndInv:
		i.AndInverted(i.decodeArgsReg3(i.instructionCounter))
	case OrInv:
		i.OrInverted(i.decodeArgsReg3(i.instructionCounter))
	case Xnor:
		i.Xnor(i.decodeArgsReg3(i.instructionCounter))
	case Max:
		i.Max(i.decodeArgsReg3(i.instructionCounter))
	case MaxU:
		i.MaxUnsigned(i.decodeArgsReg3(i.instructionCounter))
	case Min:
		i.Min(i.decodeArgsReg3(i.instructionCounter))
	case MinU:
		i.MinUnsigned(i.decodeArgsReg3(i.instructionCounter))
	default:
		// c_n if kn = 1 ∧ cn ∈ U otherwise 0 (eq. A.19 v0.7.2)
		return 0, i.Trap()
	}

	// { F if ˜ϱ′ = F ∨ ı′ < ı ∨ L(ı′) ≠ L(ı) otherwise ⊺ (eq. A.9)
	newBlockStart := i.basicBlockStart(i.instructionCounter)
	if !i.gasChange || i.instructionCounter < initialInstructionCounter || initialBlockStart != newBlockStart {
		i.gasChange = false
	} else {
		i.gasChange = true
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
