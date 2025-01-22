//go:build integration

package polkavm

import "math"

const (
	Trap                            Opcode = 0
	Fallthrough                     Opcode = 17
	Ecalli                          Opcode = 78
	StoreImmU8                      Opcode = 62
	StoreImmU16                     Opcode = 79
	StoreImmU32                     Opcode = 38
	Jump                            Opcode = 5
	JumpIndirect                    Opcode = 19
	LoadImm                         Opcode = 4
	LoadU8                          Opcode = 60
	LoadI8                          Opcode = 74
	LoadU16                         Opcode = 76
	LoadI16                         Opcode = 66
	LoadU32                         Opcode = 10
	StoreU8                         Opcode = 71
	StoreU16                        Opcode = 69
	StoreU32                        Opcode = 22
	StoreImmIndirectU8              Opcode = 26
	StoreImmIndirectU16             Opcode = 54
	StoreImmIndirectU32             Opcode = 13
	LoadImmAndJump                  Opcode = 6
	BranchEqImm                     Opcode = 7
	BranchNotEqImm                  Opcode = 15
	BranchLessUnsignedImm           Opcode = 44
	BranchLessOrEqualUnsignedImm    Opcode = 59
	BranchGreaterOrEqualUnsignedImm Opcode = 52
	BranchGreaterUnsignedImm        Opcode = 50
	BranchLessSignedImm             Opcode = 32
	BranchLessOrEqualSignedImm      Opcode = 46
	BranchGreaterOrEqualSignedImm   Opcode = 45
	BranchGreaterSignedImm          Opcode = 53
	MoveReg                         Opcode = 82
	Sbrk                            Opcode = 87
	StoreIndirectU8                 Opcode = 16
	StoreIndirectU16                Opcode = 29
	StoreIndirectU32                Opcode = 3
	LoadIndirectU8                  Opcode = 11
	LoadIndirectI8                  Opcode = 21
	LoadIndirectU16                 Opcode = 37
	LoadIndirectI16                 Opcode = 33
	LoadIndirectU32                 Opcode = 1
	AddImm32                        Opcode = 2
	AndImm                          Opcode = 18
	XorImm                          Opcode = 31
	OrImm                           Opcode = 49
	MulImm32                        Opcode = 35
	SetLessThanUnsignedImm          Opcode = 27
	SetLessThanSignedImm            Opcode = 56
	ShiftLogicalLeftImm32           Opcode = 9
	ShiftLogicalRightImm32          Opcode = 14
	ShiftArithmeticRightImm32       Opcode = 25
	NegateAndAddImm32               Opcode = 40
	SetGreaterThanUnsignedImm       Opcode = 39
	SetGreaterThanSignedImm         Opcode = 61
	ShiftLogicalRightImmAlt32       Opcode = 72
	ShiftArithmeticRightImmAlt32    Opcode = 80
	ShiftLogicalLeftImmAlt32        Opcode = 75
	CmovIfZeroImm                   Opcode = 85
	CmovIfNotZeroImm                Opcode = 86
	BranchEq                        Opcode = 24
	BranchNotEq                     Opcode = 30
	BranchLessUnsigned              Opcode = 47
	BranchLessSigned                Opcode = 48
	BranchGreaterOrEqualUnsigned    Opcode = 41
	BranchGreaterOrEqualSigned      Opcode = 43
	LoadImmAndJumpIndirect          Opcode = 42
	Add32                           Opcode = 8
	Sub32                           Opcode = 20
	Mul32                           Opcode = 34
	DivUnsigned32                   Opcode = 68
	DivSigned32                     Opcode = 64
	RemUnsigned32                   Opcode = 73
	RemSigned32                     Opcode = 70
	ShiftLogicalLeft32              Opcode = 55
	ShiftLogicalRight32             Opcode = 51
	ShiftArithmeticRight32          Opcode = 77
	And                             Opcode = 23
	Xor                             Opcode = 28
	Or                              Opcode = 12
	MulUpperSignedSigned            Opcode = 67
	MulUpperUnsignedUnsigned        Opcode = 57
	MulUpperSignedUnsigned          Opcode = 81
	SetLessThanUnsigned             Opcode = 36
	SetLessThanSigned               Opcode = 58
	CmovIfZero                      Opcode = 83
	CmovIfNotZero                   Opcode = 84
)

const (
	StoreImmIndirectU64 Opcode = math.MaxUint8 - iota
	StoreU64
	StoreImmU64
	LoadImm64
	StoreIndirectU64
	LoadIndirectI32
	LoadIndirectU64
	AddImm64
	MulImm64
	ShiftLogicalLeftImm64
	ShiftLogicalRightImm64
	ShiftArithmeticRightImm64
	NegateAndAddImm64
	ShiftLogicalLeftImmAlt64
	ShiftLogicalRightImmAlt64
	ShiftArithmeticRightImmAlt64
	Add64
	Sub64
	Mul64
	DivUnsigned64
	DivSigned64
	RemUnsigned64
	RemSigned64
	ShiftLogicalLeft64
	ShiftLogicalRight64
	ShiftArithmeticRight64
	LoadI32
	LoadU64
	CountSetBits64
	CountSetBits32
	LeadingZeroBits64
	LeadingZeroBits32
	TrailingZeroBits64
	TrailingZeroBits32
	SignExtend8
	SignExtend16
	ZeroExtend16
	ReverseBytes
	RotR64Imm
	RotR64ImmAlt
	RotR32Imm
	RotR32ImmAlt
	RotL64
	RotL32
	RotR64
	RotR32
	AndInv
	OrInv
	Xnor
	Max
	MaxU
	Min
	MinU
)
