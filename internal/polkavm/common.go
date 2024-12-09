package polkavm

import (
	"github.com/eigerco/strawberry/internal/block"
	"github.com/eigerco/strawberry/internal/common"
	"github.com/eigerco/strawberry/internal/service"
	"github.com/eigerco/strawberry/internal/state"
)

type MemoryAccess int

const (
	Inaccessible MemoryAccess = iota // ∅ (Inaccessible)
	ReadOnly                         // R (Read-Only)
	ReadWrite                        // W (Read-Write)
)

// Memory Equation: 34 (M)
type Memory struct {
	data []*memorySegment // data (V ∈ Y, A ∈ ⟦{W, R, ∅})
}

type memorySegment struct {
	start, end uint32
	access     MemoryAccess
	data       []byte
}

// Read reads from the set of readable indices (Vμ)
func (m *Memory) Read(address uint32, data []byte) error {
	memSeg := m.inRange(address)
	if memSeg == nil || memSeg.access == Inaccessible {
		return &ErrPageFault{Reason: "inaccessible memory", Address: address}
	}

	offset := int(address - memSeg.start)
	offsetEnd := offset + len(data)
	if offsetEnd > len(memSeg.data) {
		return &ErrPageFault{Reason: "memory exceeds page size, growing memory not supported", Address: address}
	}
	copy(data, memSeg.data[offset:offsetEnd])
	return nil
}

func (m *Memory) inRange(address uint32) *memorySegment {
	for _, r := range m.data {
		if address >= r.start && address <= r.end {
			return r
		}
	}
	return nil
}

func (m *Memory) Sbrk(heapTop uint32) error {
	if heapTop > m.data[2].end {
		nextPage, err := AlignToNextPage(heapTop)
		if err != nil {
			return err
		}

		m.data[2].end += nextPage
	}
	return nil
}

// Write writes to the set of writeable indices (Vμ*)
func (m *Memory) Write(address uint32, data []byte) error {
	memSeg := m.inRange(address)
	if memSeg == nil {
		return &ErrPageFault{Reason: "address not in a valid range", Address: address}
	} else if memSeg.access == ReadOnly {
		return &ErrPageFault{Reason: "memory at address is read only", Address: address}
	}
	offset := int(address - memSeg.start)
	offsetEnd := offset + len(data)
	if offsetEnd > len(memSeg.data) {
		return &ErrPageFault{Reason: "memory exceeds page size, growing memory not supported", Address: address}
	}
	copy(memSeg.data[offset:offsetEnd], data)
	return nil
}

type Registers [13]uint64

type Gas int64

// HostCall the generic Ω function definition Ωx(n, ϱ, ω, μ, x) defined in section A.6
type HostCall[X any] func(hostCall uint32, gasCounter Gas, regs Registers, mem Memory, x X) (Gas, Registers, Memory, X, error)

//go:generate go run github.com/golang/mock/mockgen --destination mutator_mock.go --package polkavm . Mutator
type Mutator interface {
	Trap() error
	Fallthrough()
	Sbrk(dst Reg, size Reg) error
	MoveReg(d Reg, s Reg)
	BranchEq(s1 Reg, s2 Reg, target uint32)
	BranchEqImm(s1 Reg, s2 uint32, target uint32)
	BranchNotEq(s1 Reg, s2 Reg, target uint32)
	BranchNotEqImm(s1 Reg, s2 uint32, target uint32)
	BranchLessUnsigned(s1 Reg, s2 Reg, target uint32)
	BranchLessUnsignedImm(s1 Reg, s2 uint32, target uint32)
	BranchLessSigned(s1 Reg, s2 Reg, target uint32)
	BranchLessSignedImm(s1 Reg, s2 uint32, target uint32)
	BranchGreaterOrEqualUnsigned(s1 Reg, s2 Reg, target uint32)
	BranchGreaterOrEqualUnsignedImm(s1 Reg, s2 uint32, target uint32)
	BranchGreaterOrEqualSigned(s1 Reg, s2 Reg, target uint32)
	BranchGreaterOrEqualSignedImm(s1 Reg, s2 uint32, target uint32)
	BranchLessOrEqualUnsignedImm(s1 Reg, s2 uint32, target uint32)
	BranchLessOrEqualSignedImm(s1 Reg, s2 uint32, target uint32)
	BranchGreaterUnsignedImm(s1 Reg, s2 uint32, target uint32)
	BranchGreaterSignedImm(s1 Reg, s2 uint32, target uint32)
	SetLessThanUnsignedImm(d Reg, s1 Reg, s2 uint32)
	SetLessThanSignedImm(d Reg, s1 Reg, s2 uint32)
	ShiftLogicalLeftImm32(d Reg, s1 Reg, s2 uint32)
	ShiftLogicalLeftImm64(d Reg, s1 Reg, s2 uint32)
	ShiftArithmeticRightImm32(d Reg, s1 Reg, s2 uint32)
	ShiftArithmeticRightImm64(d Reg, s1 Reg, s2 uint32)
	ShiftArithmeticRightImmAlt32(d Reg, s1 Reg, s2 uint32)
	ShiftArithmeticRightImmAlt64(d Reg, s1 Reg, s2 uint32)
	NegateAndAddImm32(d Reg, s1 Reg, s2 uint32)
	NegateAndAddImm64(d Reg, s1 Reg, s2 uint32)
	SetGreaterThanUnsignedImm(d Reg, s1 Reg, s2 uint32)
	SetGreaterThanSignedImm(d Reg, s1 Reg, s2 uint32)
	ShiftLogicalRightImmAlt32(d Reg, s1 Reg, s2 uint32)
	ShiftLogicalRightImmAlt64(d Reg, s1 Reg, s2 uint32)
	ShiftLogicalLeftImmAlt32(d Reg, s1 Reg, s2 uint32)
	ShiftLogicalLeftImmAlt64(d Reg, s1 Reg, s2 uint32)
	Add32(d Reg, s1, s2 Reg)
	Add64(d Reg, s1, s2 Reg)
	AddImm32(d Reg, s1 Reg, s2 uint32)
	AddImm64(d Reg, s1 Reg, s2 uint32)
	Sub32(d Reg, s1, s2 Reg)
	Sub64(d Reg, s1, s2 Reg)
	And(d Reg, s1, s2 Reg)
	AndImm(d Reg, s1 Reg, s2 uint32)
	Xor(d Reg, s1, s2 Reg)
	XorImm(d Reg, s1 Reg, s2 uint32)
	Or(d Reg, s1, s2 Reg)
	OrImm(d Reg, s1 Reg, s2 uint32)
	Mul32(d Reg, s1, s2 Reg)
	Mul64(d Reg, s1, s2 Reg)
	MulImm32(d Reg, s1 Reg, s2 uint32)
	MulImm64(d Reg, s1 Reg, s2 uint32)
	MulUpperSignedSigned(d Reg, s1, s2 Reg)
	MulUpperUnsignedUnsigned(d Reg, s1, s2 Reg)
	MulUpperSignedUnsigned(d Reg, s1, s2 Reg)
	SetLessThanUnsigned(d Reg, s1, s2 Reg)
	SetLessThanSigned(d Reg, s1, s2 Reg)
	ShiftLogicalLeft32(d Reg, s1, s2 Reg)
	ShiftLogicalLeft64(d Reg, s1, s2 Reg)
	ShiftLogicalRight32(d Reg, s1, s2 Reg)
	ShiftLogicalRight64(d Reg, s1, s2 Reg)
	ShiftLogicalRightImm32(d Reg, s1 Reg, s2 uint32)
	ShiftLogicalRightImm64(d Reg, s1 Reg, s2 uint32)
	ShiftArithmeticRight32(d Reg, s1, s2 Reg)
	ShiftArithmeticRight64(d Reg, s1, s2 Reg)
	DivUnsigned32(d Reg, s1, s2 Reg)
	DivUnsigned64(d Reg, s1, s2 Reg)
	DivSigned32(d Reg, s1, s2 Reg)
	DivSigned64(d Reg, s1, s2 Reg)
	RemUnsigned32(d Reg, s1, s2 Reg)
	RemUnsigned64(d Reg, s1, s2 Reg)
	RemSigned32(d Reg, s1, s2 Reg)
	RemSigned64(d Reg, s1, s2 Reg)
	CmovIfZero(d Reg, s, c Reg)
	CmovIfZeroImm(d Reg, c Reg, s uint32)
	CmovIfNotZero(d Reg, s, c Reg)
	CmovIfNotZeroImm(d Reg, c Reg, s uint32)
	StoreU8(src Reg, offset uint32) error
	StoreU16(src Reg, offset uint32) error
	StoreU32(src Reg, offset uint32) error
	StoreU64(src Reg, offset uint32) error
	StoreImmU8(offset uint32, value uint32) error
	StoreImmU16(offset uint32, value uint32) error
	StoreImmU32(offset uint32, value uint32) error
	StoreImmU64(offset uint32, value uint32) error
	StoreImmIndirectU8(base Reg, offset uint32, value uint32) error
	StoreImmIndirectU16(base Reg, offset uint32, value uint32) error
	StoreImmIndirectU32(base Reg, offset uint32, value uint32) error
	StoreImmIndirectU64(base Reg, offset uint32, value uint32) error
	StoreIndirectU8(src Reg, base Reg, offset uint32) error
	StoreIndirectU16(src Reg, base Reg, offset uint32) error
	StoreIndirectU32(src Reg, base Reg, offset uint32) error
	StoreIndirectU64(src Reg, base Reg, offset uint32) error
	LoadU8(dst Reg, offset uint32) error
	LoadI8(dst Reg, offset uint32) error
	LoadU16(dst Reg, offset uint32) error
	LoadI16(dst Reg, offset uint32) error
	LoadU32(dst Reg, offset uint32) error
	LoadI32(dst Reg, offset uint32) error
	LoadU64(dst Reg, offset uint32) error
	LoadIndirectU8(dst Reg, base Reg, offset uint32) error
	LoadIndirectI8(dst Reg, base Reg, offset uint32) error
	LoadIndirectU16(dst Reg, base Reg, offset uint32) error
	LoadIndirectI16(dst Reg, base Reg, offset uint32) error
	LoadIndirectU32(dst Reg, base Reg, offset uint32) error
	LoadIndirectI32(dst Reg, base Reg, offset uint32) error
	LoadIndirectU64(dst Reg, base Reg, offset uint32) error
	LoadImm(dst Reg, imm uint32)
	LoadImm64(dst Reg, imm uint64)
	LoadImmAndJump(ra Reg, value uint32, target uint32)
	LoadImmAndJumpIndirect(ra Reg, base Reg, value, offset uint32) error
	Jump(target uint32)
	JumpIndirect(base Reg, offset uint32) error
}

// AccumulateContext Equation 254
type AccumulateContext struct {
	ServiceState      service.ServiceState       // d
	ServiceId         block.ServiceId            // s
	AccumulationState state.AccumulationState    // u
	NewServiceId      block.ServiceId            // i
	DeferredTransfers []service.DeferredTransfer // t
}

// ServiceAccount x_s
func (s *AccumulateContext) ServiceAccount() service.ServiceAccount {
	return s.ServiceState[s.ServiceId]
}

type AccumulateContextPair struct {
	RegularCtx     AccumulateContext // x
	ExceptionalCtx AccumulateContext // y
}

type IntegratedPVM struct {
	Code               []byte //p program code
	Ram                Memory //u RAM
	InstructionCounter uint32 //i  instruction counter
}

type Segment [common.SizeOfExportedSegment]byte

type RefineContextPair struct {
	IntegratedPVMMap map[uint64]IntegratedPVM //m
	Segments         []Segment                //e
}
