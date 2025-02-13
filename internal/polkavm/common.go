package polkavm

import (
	"github.com/eigerco/strawberry/internal/block"
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/service"
	"github.com/eigerco/strawberry/internal/state"
	"github.com/eigerco/strawberry/internal/work"
)

type MemoryAccess int

const (
	Inaccessible MemoryAccess = iota // ∅ (Inaccessible)
	ReadOnly                         // R (Read-Only)
	ReadWrite                        // W (Read-Write)
)

// Memory M ≡ (V ∈ Y_(2^32), A ∈ ⟦{W, R, ∅}⟧p) (eq. 4.24)
// for practical reasons we define each memory segment separately
// so we don't have to allocate [2^32]byte unnecessarily
type Memory struct {
	ro    memorySegment
	rw    memorySegment
	stack memorySegment
	args  memorySegment
}

type memorySegment struct {
	address uint32
	data    []byte
	access  MemoryAccess
}

// Read reads from the set of readable indices (Vμ) (implements eq. A.8)
func (m *Memory) Read(address uint32, data []byte) error {
	// ☇ if min(x) mod 2^32 < 2^16
	if address < 1<<16 {
		return ErrPanicf("forbidden memory access")
	}
	var memoryData []byte
	access := Inaccessible
	if address >= m.stack.address && address+uint32(len(data)) <= m.stack.address+uint32(len(m.stack.data)) {
		memoryData = m.stack.data[address-m.stack.address : address-m.stack.address+uint32(len(data))]
		access = m.stack.access
	} else if address >= m.rw.address && address+uint32(len(data)) <= m.rw.address+uint32(len(m.rw.data)) {
		memoryData = m.rw.data[address-m.rw.address : address-m.rw.address+uint32(len(data))]
		access = m.rw.access
	} else if address >= m.ro.address && address+uint32(len(data)) <= m.ro.address+uint32(len(m.ro.data)) {
		memoryData = m.ro.data[address-m.ro.address : address-m.ro.address+uint32(len(data))]
		access = m.ro.access
	} else if address >= m.args.address && address+uint32(len(data)) <= m.args.address+uint32(len(m.args.data)) {
		memoryData = m.args.data[address-m.args.address : address-m.args.address+uint32(len(data))]
		access = m.args.access
	}

	// F × ZP ⌊ min(x) mod 2^32 ÷ ZP ⌋
	if access == Inaccessible {
		return &ErrPageFault{Reason: "inaccessible memory", Address: alignToPage(address)}
	}
	copy(data, memoryData)
	return nil
}

// Write writes to the set of writeable indices (Vμ*) (implements eq. A.8)
func (m *Memory) Write(address uint32, data []byte) error {
	// ☇ if min(x) mod 2^32 < 2^16
	if address < 1<<16 {
		return ErrPanicf("forbidden memory access")
	}

	var memoryData []byte
	access := Inaccessible
	if address >= m.stack.address && address+uint32(len(data)) <= m.stack.address+uint32(len(m.stack.data)) {
		memoryData = m.stack.data[address-m.stack.address : address-m.stack.address+uint32(len(data))]
		access = m.stack.access
	} else if address >= m.rw.address && address+uint32(len(data)) <= m.rw.address+uint32(len(m.rw.data)) {
		memoryData = m.rw.data[address-m.rw.address : address-m.rw.address+uint32(len(data))]
		access = m.rw.access
	} else if address >= m.ro.address && address+uint32(len(data)) <= m.ro.address+uint32(len(m.ro.data)) {
		memoryData = m.ro.data[address-m.ro.address : address-m.ro.address+uint32(len(data))]
		access = m.ro.access
	} else if address >= m.args.address && address+uint32(len(data)) <= m.args.address+uint32(len(m.args.data)) {
		memoryData = m.args.data[address-m.args.address : address-m.args.address+uint32(len(data))]
		access = m.args.access
	}

	// F × ZP ⌊ min(x) mod 2^32 ÷ ZP ⌋
	if access != ReadWrite {
		return &ErrPageFault{Reason: "memory at address is not writeable", Address: alignToPage(address)}
	}
	copy(memoryData, data)
	return nil
}

func (m *Memory) Sbrk(size uint32) (uint32, error) {
	currentHeapPointer := m.rw.address + uint32(len(m.rw.data)) // h
	if size == 0 {
		return currentHeapPointer, nil
	}

	newHeapPointer := currentHeapPointer + size
	if newHeapPointer >= m.stack.address { // where the next memory segment begins
		return 0, &ErrPageFault{Reason: "allocation failed heap pointer exceeds maximum allowed", Address: newHeapPointer}
	}

	if newHeapPointer > currentHeapPointer {
		m.rw.data = make([]byte, alignToPage(newHeapPointer))
	}

	return m.rw.address + uint32(len(m.rw.data)), nil
}

// SetAccess updates the access mode
func (m *Memory) SetAccess(pageIndex uint32, access MemoryAccess) error {
	address := pageIndex * PageSize

	if address >= m.stack.address && address <= m.stack.address+uint32(len(m.stack.data)) {
		m.stack.access = access
		return nil
	} else if address >= m.rw.address && address <= m.rw.address+uint32(len(m.rw.data)) {
		m.rw.access = access
		return nil
	} else if address >= m.ro.address && address <= m.ro.address+uint32(len(m.ro.data)) {
		m.ro.access = access
		return nil
	} else if address >= m.args.address && address <= m.args.address+uint32(len(m.args.data)) {
		m.args.access = access
		return nil
	}

	return &ErrPageFault{Reason: "page out of valid range", Address: address}
}

func (m *Memory) GetAccess(pageIndex uint32) MemoryAccess {
	address := pageIndex * PageSize

	if address >= m.stack.address && address <= m.stack.address+uint32(len(m.stack.data)) {
		return m.stack.access
	} else if address >= m.rw.address && address <= m.rw.address+uint32(len(m.rw.data)) {
		return m.rw.access
	} else if address >= m.ro.address && address <= m.ro.address+uint32(len(m.ro.data)) {
		return m.ro.access
	} else if address >= m.args.address && address <= m.args.address+uint32(len(m.args.data)) {
		return m.args.access
	}

	return Inaccessible
}

type Registers [13]uint64

type Gas int64

// HostCall the generic Ω function definition Ωx(n, ϱ, ω, μ, x) defined in section A.6
type HostCall[X any] func(hostCall uint32, gasCounter Gas, regs Registers, mem Memory, x X) (Gas, Registers, Memory, X, error)

type Mutator interface {
	Trap() error
	Fallthrough()

	LoadImm64(Reg, uint64)

	StoreImmU8(uint32, uint32) error
	StoreImmU16(uint32, uint32) error
	StoreImmU32(uint32, uint32) error
	StoreImmU64(uint32, uint32) error

	Jump(uint32) error

	JumpIndirect(Reg, uint32) error
	LoadImm(Reg, uint32)
	LoadU8(Reg, uint32) error
	LoadI8(Reg, uint32) error
	LoadU16(Reg, uint32) error
	LoadI16(Reg, uint32) error
	LoadU32(Reg, uint32) error
	LoadI32(Reg, uint32) error
	LoadU64(Reg, uint32) error
	StoreU8(Reg, uint32) error
	StoreU16(Reg, uint32) error
	StoreU32(Reg, uint32) error
	StoreU64(Reg, uint32) error

	StoreImmIndirectU8(Reg, uint32, uint32) error
	StoreImmIndirectU16(Reg, uint32, uint32) error
	StoreImmIndirectU32(Reg, uint32, uint32) error
	StoreImmIndirectU64(Reg, uint32, uint32) error

	LoadImmAndJump(Reg, uint32, uint32) error
	BranchEqImm(Reg, uint32, uint32) error
	BranchNotEqImm(Reg, uint32, uint32) error
	BranchLessUnsignedImm(Reg, uint32, uint32) error
	BranchLessOrEqualUnsignedImm(Reg, uint32, uint32) error
	BranchGreaterOrEqualUnsignedImm(Reg, uint32, uint32) error
	BranchGreaterUnsignedImm(Reg, uint32, uint32) error
	BranchLessSignedImm(Reg, uint32, uint32) error
	BranchLessOrEqualSignedImm(Reg, uint32, uint32) error
	BranchGreaterOrEqualSignedImm(Reg, uint32, uint32) error
	BranchGreaterSignedImm(Reg, uint32, uint32) error

	MoveReg(Reg, Reg)
	Sbrk(Reg, Reg) error
	CountSetBits64(Reg, Reg)
	CountSetBits32(Reg, Reg)
	LeadingZeroBits64(Reg, Reg)
	LeadingZeroBits32(Reg, Reg)
	TrailingZeroBits64(Reg, Reg)
	TrailingZeroBits32(Reg, Reg)
	SignExtend8(Reg, Reg)
	SignExtend16(Reg, Reg)
	ZeroExtend16(Reg, Reg)
	ReverseBytes(Reg, Reg)

	StoreIndirectU8(Reg, Reg, uint32) error
	StoreIndirectU16(Reg, Reg, uint32) error
	StoreIndirectU32(Reg, Reg, uint32) error
	StoreIndirectU64(Reg, Reg, uint32) error
	LoadIndirectU8(Reg, Reg, uint32) error
	LoadIndirectI8(Reg, Reg, uint32) error
	LoadIndirectU16(Reg, Reg, uint32) error
	LoadIndirectI16(Reg, Reg, uint32) error
	LoadIndirectU32(Reg, Reg, uint32) error
	LoadIndirectI32(Reg, Reg, uint32) error
	LoadIndirectU64(Reg, Reg, uint32) error
	AddImm32(Reg, Reg, uint32)
	AndImm(Reg, Reg, uint32)
	XorImm(Reg, Reg, uint32)
	OrImm(Reg, Reg, uint32)
	MulImm32(Reg, Reg, uint32)
	SetLessThanUnsignedImm(Reg, Reg, uint32)
	SetLessThanSignedImm(Reg, Reg, uint32)
	ShiftLogicalLeftImm32(Reg, Reg, uint32)
	ShiftLogicalRightImm32(Reg, Reg, uint32)
	ShiftArithmeticRightImm32(Reg, Reg, uint32)
	NegateAndAddImm32(Reg, Reg, uint32)
	SetGreaterThanUnsignedImm(Reg, Reg, uint32)
	SetGreaterThanSignedImm(Reg, Reg, uint32)
	ShiftLogicalLeftImmAlt32(Reg, Reg, uint32)
	ShiftLogicalRightImmAlt32(Reg, Reg, uint32)
	ShiftArithmeticRightImmAlt32(Reg, Reg, uint32)
	CmovIfZeroImm(Reg, Reg, uint32)
	CmovIfNotZeroImm(Reg, Reg, uint32)
	AddImm64(Reg, Reg, uint32)
	MulImm64(Reg, Reg, uint32)
	ShiftLogicalLeftImm64(Reg, Reg, uint32)
	ShiftLogicalRightImm64(Reg, Reg, uint32)
	ShiftArithmeticRightImm64(Reg, Reg, uint32)
	NegateAndAddImm64(Reg, Reg, uint32)
	ShiftLogicalLeftImmAlt64(Reg, Reg, uint32)
	ShiftLogicalRightImmAlt64(Reg, Reg, uint32)
	ShiftArithmeticRightImmAlt64(Reg, Reg, uint32)
	RotateRight64Imm(Reg, Reg, uint32)
	RotateRight64ImmAlt(Reg, Reg, uint32)
	RotateRight32Imm(Reg, Reg, uint32)
	RotateRight32ImmAlt(Reg, Reg, uint32)

	BranchEq(Reg, Reg, uint32) error
	BranchNotEq(Reg, Reg, uint32) error
	BranchLessUnsigned(Reg, Reg, uint32) error
	BranchLessSigned(Reg, Reg, uint32) error
	BranchGreaterOrEqualUnsigned(Reg, Reg, uint32) error
	BranchGreaterOrEqualSigned(Reg, Reg, uint32) error

	LoadImmAndJumpIndirect(Reg, Reg, uint32, uint32) error

	Add32(Reg, Reg, Reg)
	Sub32(Reg, Reg, Reg)
	Mul32(Reg, Reg, Reg)
	DivUnsigned32(Reg, Reg, Reg)
	DivSigned32(Reg, Reg, Reg)
	RemUnsigned32(Reg, Reg, Reg)
	RemSigned32(Reg, Reg, Reg)
	ShiftLogicalLeft32(Reg, Reg, Reg)
	ShiftLogicalRight32(Reg, Reg, Reg)
	ShiftArithmeticRight32(Reg, Reg, Reg)
	Add64(Reg, Reg, Reg)
	Sub64(Reg, Reg, Reg)
	Mul64(Reg, Reg, Reg)
	DivUnsigned64(Reg, Reg, Reg)
	DivSigned64(Reg, Reg, Reg)
	RemUnsigned64(Reg, Reg, Reg)
	RemSigned64(Reg, Reg, Reg)
	ShiftLogicalLeft64(Reg, Reg, Reg)
	ShiftLogicalRight64(Reg, Reg, Reg)
	ShiftArithmeticRight64(Reg, Reg, Reg)
	And(Reg, Reg, Reg)
	Xor(Reg, Reg, Reg)
	Or(Reg, Reg, Reg)
	MulUpperSignedSigned(Reg, Reg, Reg)
	MulUpperUnsignedUnsigned(Reg, Reg, Reg)
	MulUpperSignedUnsigned(Reg, Reg, Reg)
	SetLessThanUnsigned(Reg, Reg, Reg)
	SetLessThanSigned(Reg, Reg, Reg)
	CmovIfZero(Reg, Reg, Reg)
	CmovIfNotZero(Reg, Reg, Reg)
	RotateLeft64(Reg, Reg, Reg)
	RotateLeft32(Reg, Reg, Reg)
	RotateRight64(Reg, Reg, Reg)
	RotateRight32(Reg, Reg, Reg)
	AndInverted(Reg, Reg, Reg)
	OrInverted(Reg, Reg, Reg)
	Xnor(Reg, Reg, Reg)
	Max(Reg, Reg, Reg)
	MaxUnsigned(Reg, Reg, Reg)
	Min(Reg, Reg, Reg)
	MinUnsigned(Reg, Reg, Reg)
}

// AccumulateContext B.6 (v0.5.4)
type AccumulateContext struct {
	ServiceId         block.ServiceId            // s
	AccumulationState state.AccumulationState    // u
	NewServiceId      block.ServiceId            // i
	DeferredTransfers []service.DeferredTransfer // t
	AccumulationHash  *crypto.Hash               // y
}

// ServiceAccount x_s
func (s *AccumulateContext) ServiceAccount() service.ServiceAccount {
	return s.AccumulationState.ServiceState[s.ServiceId]
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

type RefineContextPair struct {
	IntegratedPVMMap map[uint64]IntegratedPVM //m
	Segments         []work.Segment           //e
}
