package polkavm

import (
	"github.com/eigerco/strawberry/internal/block"
	"github.com/eigerco/strawberry/internal/service"
	"github.com/eigerco/strawberry/internal/state"
)

type MemoryAccess bool

const (
	ReadOnly  MemoryAccess = false // (R)
	ReadWrite MemoryAccess = true  // (W)
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
	if memSeg == nil {
		return &ErrPageFault{Reason: "address not in a valid range", Address: address}
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

func (m *Memory) Sbrk(pageSize, heapTop uint32) error {
	if heapTop > m.data[2].end {
		nextPage, err := AlignToNextPage(uint(pageSize), uint(heapTop))
		if err != nil {
			return err
		}

		m.data[2].end += uint32(nextPage)
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

type Registers [13]uint32

type Gas int64

// HostCall the generic Ω function definition Ωx(n, ξ, ω, μ, x) defined in section A.6
type HostCall[X any] func(hostCall uint32, gasCounter Gas, regs Registers, mem Memory, x X) (Gas, Registers, Memory, X, error)

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
	ShiftLogicalLeftImm(d Reg, s1 Reg, s2 uint32)
	ShiftArithmeticRightImm(d Reg, s1 Reg, s2 uint32)
	ShiftArithmeticRightImmAlt(d Reg, s1 Reg, s2 uint32)
	NegateAndAddImm(d Reg, s1 Reg, s2 uint32)
	SetGreaterThanUnsignedImm(d Reg, s1 Reg, s2 uint32)
	SetGreaterThanSignedImm(d Reg, s1 Reg, s2 uint32)
	ShiftLogicalRightImmAlt(d Reg, s1 Reg, s2 uint32)
	ShiftLogicalLeftImmAlt(d Reg, s1 Reg, s2 uint32)
	Add(d Reg, s1, s2 Reg)
	AddImm(d Reg, s1 Reg, s2 uint32)
	Sub(d Reg, s1, s2 Reg)
	And(d Reg, s1, s2 Reg)
	AndImm(d Reg, s1 Reg, s2 uint32)
	Xor(d Reg, s1, s2 Reg)
	XorImm(d Reg, s1 Reg, s2 uint32)
	Or(d Reg, s1, s2 Reg)
	OrImm(d Reg, s1 Reg, s2 uint32)
	Mul(d Reg, s1, s2 Reg)
	MulImm(d Reg, s1 Reg, s2 uint32)
	MulUpperSignedSigned(d Reg, s1, s2 Reg)
	MulUpperSignedSignedImm(d Reg, s1 Reg, s2 uint32)
	MulUpperUnsignedUnsigned(d Reg, s1, s2 Reg)
	MulUpperUnsignedUnsignedImm(d Reg, s1 Reg, s2 uint32)
	MulUpperSignedUnsigned(d Reg, s1, s2 Reg)
	SetLessThanUnsigned(d Reg, s1, s2 Reg)
	SetLessThanSigned(d Reg, s1, s2 Reg)
	ShiftLogicalLeft(d Reg, s1, s2 Reg)
	ShiftLogicalRight(d Reg, s1, s2 Reg)
	ShiftLogicalRightImm(d Reg, s1 Reg, s2 uint32)
	ShiftArithmeticRight(d Reg, s1, s2 Reg)
	DivUnsigned(d Reg, s1, s2 Reg)
	DivSigned(d Reg, s1, s2 Reg)
	RemUnsigned(d Reg, s1, s2 Reg)
	RemSigned(d Reg, s1, s2 Reg)
	CmovIfZero(d Reg, s, c Reg)
	CmovIfZeroImm(d Reg, c Reg, s uint32)
	CmovIfNotZero(d Reg, s, c Reg)
	CmovIfNotZeroImm(d Reg, c Reg, s uint32)
	StoreU8(src Reg, offset uint32) error
	StoreU16(src Reg, offset uint32) error
	StoreU32(src Reg, offset uint32) error
	StoreImmU8(offset uint32, value uint32) error
	StoreImmU16(offset uint32, value uint32) error
	StoreImmU32(offset uint32, value uint32) error
	StoreImmIndirectU8(base Reg, offset uint32, value uint32) error
	StoreImmIndirectU16(base Reg, offset uint32, value uint32) error
	StoreImmIndirectU32(base Reg, offset uint32, value uint32) error
	StoreIndirectU8(src Reg, base Reg, offset uint32) error
	StoreIndirectU16(src Reg, base Reg, offset uint32) error
	StoreIndirectU32(src Reg, base Reg, offset uint32) error
	LoadU8(dst Reg, offset uint32) error
	LoadI8(dst Reg, offset uint32) error
	LoadU16(dst Reg, offset uint32) error
	LoadI16(dst Reg, offset uint32) error
	LoadU32(dst Reg, offset uint32) error
	LoadIndirectU8(dst Reg, base Reg, offset uint32) error
	LoadIndirectI8(dst Reg, base Reg, offset uint32) error
	LoadIndirectU16(dst Reg, base Reg, offset uint32) error
	LoadIndirectI16(dst Reg, base Reg, offset uint32) error
	LoadIndirectU32(dst Reg, base Reg, offset uint32) error
	LoadImm(dst Reg, imm uint32)
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
