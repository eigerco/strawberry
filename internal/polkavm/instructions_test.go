package polkavm

import (
	"errors"
	"slices"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
)

func TestInstruction_Mutate(t *testing.T) {
	allInstrOpcodes := slices.Concat(
		instrImm, instrNone, instrImm,
		instrRegImmExt, instrImm2, instrOffset,
		instrRegImm, instrRegImm2, instrRegImmOffset,
		instrRegReg, instrReg2Imm, instrReg2Offset,
		instrReg2Imm2, instrReg3)

	ctrl := gomock.NewController(t)
	mutator := NewMockMutator(ctrl)

	mutator.EXPECT().Trap().Times(1)
	mutator.EXPECT().Fallthrough().Return().Times(1)
	mutator.EXPECT().Sbrk(gomock.Any(), gomock.Any()).Times(1)
	mutator.EXPECT().MoveReg(gomock.Any(), gomock.Any()).Times(1)
	mutator.EXPECT().BranchEq(gomock.Any(), gomock.Any(), gomock.Any()).Times(1)
	mutator.EXPECT().BranchEqImm(gomock.Any(), gomock.Any(), gomock.Any()).Times(1)
	mutator.EXPECT().BranchNotEq(gomock.Any(), gomock.Any(), gomock.Any()).Times(1)
	mutator.EXPECT().BranchNotEqImm(gomock.Any(), gomock.Any(), gomock.Any()).Times(1)
	mutator.EXPECT().BranchLessUnsigned(gomock.Any(), gomock.Any(), gomock.Any()).Times(1)
	mutator.EXPECT().BranchLessUnsignedImm(gomock.Any(), gomock.Any(), gomock.Any()).Times(1)
	mutator.EXPECT().BranchLessSigned(gomock.Any(), gomock.Any(), gomock.Any()).Times(1)
	mutator.EXPECT().BranchLessSignedImm(gomock.Any(), gomock.Any(), gomock.Any()).Times(1)
	mutator.EXPECT().BranchGreaterOrEqualUnsigned(gomock.Any(), gomock.Any(), gomock.Any()).Times(1)
	mutator.EXPECT().BranchGreaterOrEqualUnsignedImm(gomock.Any(), gomock.Any(), gomock.Any()).Times(1)
	mutator.EXPECT().BranchGreaterOrEqualSigned(gomock.Any(), gomock.Any(), gomock.Any()).Times(1)
	mutator.EXPECT().BranchGreaterOrEqualSignedImm(gomock.Any(), gomock.Any(), gomock.Any()).Times(1)
	mutator.EXPECT().BranchLessOrEqualUnsignedImm(gomock.Any(), gomock.Any(), gomock.Any()).Times(1)
	mutator.EXPECT().BranchLessOrEqualSignedImm(gomock.Any(), gomock.Any(), gomock.Any()).Times(1)
	mutator.EXPECT().BranchGreaterUnsignedImm(gomock.Any(), gomock.Any(), gomock.Any()).Times(1)
	mutator.EXPECT().BranchGreaterSignedImm(gomock.Any(), gomock.Any(), gomock.Any()).Times(1)
	mutator.EXPECT().SetLessThanUnsignedImm(gomock.Any(), gomock.Any(), gomock.Any()).Times(1)
	mutator.EXPECT().SetLessThanSignedImm(gomock.Any(), gomock.Any(), gomock.Any()).Times(1)
	mutator.EXPECT().ShiftLogicalLeftImm32(gomock.Any(), gomock.Any(), gomock.Any()).Times(1)
	mutator.EXPECT().ShiftLogicalLeftImm64(gomock.Any(), gomock.Any(), gomock.Any()).Times(1)
	mutator.EXPECT().ShiftArithmeticRightImm32(gomock.Any(), gomock.Any(), gomock.Any()).Times(1)
	mutator.EXPECT().ShiftArithmeticRightImm64(gomock.Any(), gomock.Any(), gomock.Any()).Times(1)
	mutator.EXPECT().ShiftArithmeticRightImmAlt32(gomock.Any(), gomock.Any(), gomock.Any()).Times(1)
	mutator.EXPECT().ShiftArithmeticRightImmAlt64(gomock.Any(), gomock.Any(), gomock.Any()).Times(1)
	mutator.EXPECT().NegateAndAddImm32(gomock.Any(), gomock.Any(), gomock.Any()).Times(1)
	mutator.EXPECT().NegateAndAddImm64(gomock.Any(), gomock.Any(), gomock.Any()).Times(1)
	mutator.EXPECT().SetGreaterThanUnsignedImm(gomock.Any(), gomock.Any(), gomock.Any()).Times(1)
	mutator.EXPECT().SetGreaterThanSignedImm(gomock.Any(), gomock.Any(), gomock.Any()).Times(1)
	mutator.EXPECT().ShiftLogicalRightImmAlt32(gomock.Any(), gomock.Any(), gomock.Any()).Times(1)
	mutator.EXPECT().ShiftLogicalRightImmAlt64(gomock.Any(), gomock.Any(), gomock.Any()).Times(1)
	mutator.EXPECT().ShiftLogicalLeftImmAlt32(gomock.Any(), gomock.Any(), gomock.Any()).Times(1)
	mutator.EXPECT().ShiftLogicalLeftImmAlt64(gomock.Any(), gomock.Any(), gomock.Any()).Times(1)
	mutator.EXPECT().Add32(gomock.Any(), gomock.Any(), gomock.Any()).Times(1)
	mutator.EXPECT().Add64(gomock.Any(), gomock.Any(), gomock.Any()).Times(1)
	mutator.EXPECT().AddImm32(gomock.Any(), gomock.Any(), gomock.Any()).Times(1)
	mutator.EXPECT().AddImm64(gomock.Any(), gomock.Any(), gomock.Any()).Times(1)
	mutator.EXPECT().Sub32(gomock.Any(), gomock.Any(), gomock.Any()).Times(1)
	mutator.EXPECT().Sub64(gomock.Any(), gomock.Any(), gomock.Any()).Times(1)
	mutator.EXPECT().And(gomock.Any(), gomock.Any(), gomock.Any()).Times(1)
	mutator.EXPECT().AndImm(gomock.Any(), gomock.Any(), gomock.Any()).Times(1)
	mutator.EXPECT().Xor(gomock.Any(), gomock.Any(), gomock.Any()).Times(1)
	mutator.EXPECT().XorImm(gomock.Any(), gomock.Any(), gomock.Any()).Times(1)
	mutator.EXPECT().Or(gomock.Any(), gomock.Any(), gomock.Any()).Times(1)
	mutator.EXPECT().OrImm(gomock.Any(), gomock.Any(), gomock.Any()).Times(1)
	mutator.EXPECT().Mul32(gomock.Any(), gomock.Any(), gomock.Any()).Times(1)
	mutator.EXPECT().Mul64(gomock.Any(), gomock.Any(), gomock.Any()).Times(1)
	mutator.EXPECT().MulImm32(gomock.Any(), gomock.Any(), gomock.Any()).Times(1)
	mutator.EXPECT().MulImm64(gomock.Any(), gomock.Any(), gomock.Any()).Times(1)
	mutator.EXPECT().MulUpperSignedSigned(gomock.Any(), gomock.Any(), gomock.Any()).Times(1)
	mutator.EXPECT().MulUpperUnsignedUnsigned(gomock.Any(), gomock.Any(), gomock.Any()).Times(1)
	mutator.EXPECT().MulUpperSignedUnsigned(gomock.Any(), gomock.Any(), gomock.Any()).Times(1)
	mutator.EXPECT().SetLessThanUnsigned(gomock.Any(), gomock.Any(), gomock.Any()).Times(1)
	mutator.EXPECT().SetLessThanSigned(gomock.Any(), gomock.Any(), gomock.Any()).Times(1)
	mutator.EXPECT().ShiftLogicalLeft32(gomock.Any(), gomock.Any(), gomock.Any()).Times(1)
	mutator.EXPECT().ShiftLogicalLeft64(gomock.Any(), gomock.Any(), gomock.Any()).Times(1)
	mutator.EXPECT().ShiftLogicalRight32(gomock.Any(), gomock.Any(), gomock.Any()).Times(1)
	mutator.EXPECT().ShiftLogicalRight64(gomock.Any(), gomock.Any(), gomock.Any()).Times(1)
	mutator.EXPECT().ShiftLogicalRightImm32(gomock.Any(), gomock.Any(), gomock.Any()).Times(1)
	mutator.EXPECT().ShiftLogicalRightImm64(gomock.Any(), gomock.Any(), gomock.Any()).Times(1)
	mutator.EXPECT().ShiftArithmeticRight32(gomock.Any(), gomock.Any(), gomock.Any()).Times(1)
	mutator.EXPECT().ShiftArithmeticRight64(gomock.Any(), gomock.Any(), gomock.Any()).Times(1)
	mutator.EXPECT().DivUnsigned32(gomock.Any(), gomock.Any(), gomock.Any()).Times(1)
	mutator.EXPECT().DivUnsigned64(gomock.Any(), gomock.Any(), gomock.Any()).Times(1)
	mutator.EXPECT().DivSigned32(gomock.Any(), gomock.Any(), gomock.Any()).Times(1)
	mutator.EXPECT().DivSigned64(gomock.Any(), gomock.Any(), gomock.Any()).Times(1)
	mutator.EXPECT().RemUnsigned32(gomock.Any(), gomock.Any(), gomock.Any()).Times(1)
	mutator.EXPECT().RemUnsigned64(gomock.Any(), gomock.Any(), gomock.Any()).Times(1)
	mutator.EXPECT().RemSigned32(gomock.Any(), gomock.Any(), gomock.Any()).Times(1)
	mutator.EXPECT().RemSigned64(gomock.Any(), gomock.Any(), gomock.Any()).Times(1)
	mutator.EXPECT().CmovIfZero(gomock.Any(), gomock.Any(), gomock.Any()).Times(1)
	mutator.EXPECT().CmovIfZeroImm(gomock.Any(), gomock.Any(), gomock.Any()).Times(1)
	mutator.EXPECT().CmovIfNotZero(gomock.Any(), gomock.Any(), gomock.Any()).Times(1)
	mutator.EXPECT().CmovIfNotZeroImm(gomock.Any(), gomock.Any(), gomock.Any()).Times(1)
	mutator.EXPECT().StoreU8(gomock.Any(), gomock.Any()).Times(1)
	mutator.EXPECT().StoreU16(gomock.Any(), gomock.Any()).Times(1)
	mutator.EXPECT().StoreU32(gomock.Any(), gomock.Any()).Times(1)
	mutator.EXPECT().StoreU64(gomock.Any(), gomock.Any()).Times(1)
	mutator.EXPECT().StoreImmU8(gomock.Any(), gomock.Any()).Times(1)
	mutator.EXPECT().StoreImmU16(gomock.Any(), gomock.Any()).Times(1)
	mutator.EXPECT().StoreImmU32(gomock.Any(), gomock.Any()).Times(1)
	mutator.EXPECT().StoreImmU64(gomock.Any(), gomock.Any()).Times(1)
	mutator.EXPECT().StoreImmIndirectU8(gomock.Any(), gomock.Any(), gomock.Any()).Times(1)
	mutator.EXPECT().StoreImmIndirectU16(gomock.Any(), gomock.Any(), gomock.Any()).Times(1)
	mutator.EXPECT().StoreImmIndirectU32(gomock.Any(), gomock.Any(), gomock.Any()).Times(1)
	mutator.EXPECT().StoreImmIndirectU64(gomock.Any(), gomock.Any(), gomock.Any()).Times(1)
	mutator.EXPECT().StoreIndirectU8(gomock.Any(), gomock.Any(), gomock.Any()).Times(1)
	mutator.EXPECT().StoreIndirectU16(gomock.Any(), gomock.Any(), gomock.Any()).Times(1)
	mutator.EXPECT().StoreIndirectU32(gomock.Any(), gomock.Any(), gomock.Any()).Times(1)
	mutator.EXPECT().StoreIndirectU64(gomock.Any(), gomock.Any(), gomock.Any()).Times(1)
	mutator.EXPECT().LoadU8(gomock.Any(), gomock.Any()).Times(1)
	mutator.EXPECT().LoadI8(gomock.Any(), gomock.Any()).Times(1)
	mutator.EXPECT().LoadU16(gomock.Any(), gomock.Any()).Times(1)
	mutator.EXPECT().LoadI16(gomock.Any(), gomock.Any()).Times(1)
	mutator.EXPECT().LoadU32(gomock.Any(), gomock.Any()).Times(1)
	mutator.EXPECT().LoadI32(gomock.Any(), gomock.Any()).Times(1)
	mutator.EXPECT().LoadU64(gomock.Any(), gomock.Any()).Times(1)
	mutator.EXPECT().LoadIndirectU8(gomock.Any(), gomock.Any(), gomock.Any()).Times(1)
	mutator.EXPECT().LoadIndirectI8(gomock.Any(), gomock.Any(), gomock.Any()).Times(1)
	mutator.EXPECT().LoadIndirectU16(gomock.Any(), gomock.Any(), gomock.Any()).Times(1)
	mutator.EXPECT().LoadIndirectI16(gomock.Any(), gomock.Any(), gomock.Any()).Times(1)
	mutator.EXPECT().LoadIndirectU32(gomock.Any(), gomock.Any(), gomock.Any()).Times(1)
	mutator.EXPECT().LoadIndirectI32(gomock.Any(), gomock.Any(), gomock.Any()).Times(1)
	mutator.EXPECT().LoadIndirectU64(gomock.Any(), gomock.Any(), gomock.Any()).Times(1)
	mutator.EXPECT().LoadImm(gomock.Any(), gomock.Any()).Times(1)
	mutator.EXPECT().LoadImmAndJump(gomock.Any(), gomock.Any(), gomock.Any()).Times(1)
	mutator.EXPECT().LoadImmAndJumpIndirect(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Times(1)
	mutator.EXPECT().Jump(gomock.Any()).Times(1)
	mutator.EXPECT().JumpIndirect(gomock.Any(), gomock.Any()).Times(1)
	mutator.EXPECT().LoadImm64(gomock.Any(), gomock.Any()).Times(1)
	mutator.EXPECT().CountSetBits64(gomock.Any(), gomock.Any())
	mutator.EXPECT().CountSetBits32(gomock.Any(), gomock.Any())
	mutator.EXPECT().LeadingZeroBits64(gomock.Any(), gomock.Any())
	mutator.EXPECT().LeadingZeroBits32(gomock.Any(), gomock.Any())
	mutator.EXPECT().TrailingZeroBits64(gomock.Any(), gomock.Any())
	mutator.EXPECT().TrailingZeroBits32(gomock.Any(), gomock.Any())
	mutator.EXPECT().SignExtend8(gomock.Any(), gomock.Any())
	mutator.EXPECT().SignExtend16(gomock.Any(), gomock.Any())
	mutator.EXPECT().ZeroExtend16(gomock.Any(), gomock.Any())
	mutator.EXPECT().ReverseBytes(gomock.Any(), gomock.Any())
	mutator.EXPECT().RotateRight64Imm(gomock.Any(), gomock.Any(), gomock.Any())
	mutator.EXPECT().RotateRight64ImmAlt(gomock.Any(), gomock.Any(), gomock.Any())
	mutator.EXPECT().RotateRight32Imm(gomock.Any(), gomock.Any(), gomock.Any())
	mutator.EXPECT().RotateRight32ImmAlt(gomock.Any(), gomock.Any(), gomock.Any())
	mutator.EXPECT().RotateLeft64(gomock.Any(), gomock.Any(), gomock.Any())
	mutator.EXPECT().RotateLeft32(gomock.Any(), gomock.Any(), gomock.Any())
	mutator.EXPECT().RotateRight64(gomock.Any(), gomock.Any(), gomock.Any())
	mutator.EXPECT().RotateRight32(gomock.Any(), gomock.Any(), gomock.Any())
	mutator.EXPECT().AndInverted(gomock.Any(), gomock.Any(), gomock.Any())
	mutator.EXPECT().OrInverted(gomock.Any(), gomock.Any(), gomock.Any())
	mutator.EXPECT().Xnor(gomock.Any(), gomock.Any(), gomock.Any())
	mutator.EXPECT().Max(gomock.Any(), gomock.Any(), gomock.Any())
	mutator.EXPECT().MaxUnsigned(gomock.Any(), gomock.Any(), gomock.Any())
	mutator.EXPECT().Min(gomock.Any(), gomock.Any(), gomock.Any())
	mutator.EXPECT().MinUnsigned(gomock.Any(), gomock.Any(), gomock.Any())

	for _, opcode := range allInstrOpcodes {
		instr := Instruction{
			Opcode: opcode,
			Imm:    []uint32{0, 0, 0},
			ExtImm: 0,
			Reg:    []Reg{RA, SP, T0},
			Offset: 0,
			Length: 0,
		}

		_, err := instr.Mutate(mutator)
		if !errors.Is(err, ErrHostCall) {
			assert.NoError(t, err)
		}
	}
	ctrl.Finish()
}
