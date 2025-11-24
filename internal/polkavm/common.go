package polkavm

import (
	"bytes"

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

// Memory M ≡ (v ∈ B_(2^32), a ∈ ⟦{W, R, ∅}⟧p) (eq. 4.24 v0.7.0)
// for practical reasons we define each memory segment separately
// so we don't have to allocate [2^32]byte unnecessarily
type Memory struct {
	ro                 memorySegment
	rw                 memorySegment
	stack              memorySegment
	args               memorySegment
	currentHeapPointer uint64
}

type memorySegment struct {
	address uint64
	data    []byte
	access  MemoryAccess
}

// Read reads from the set of readable indices (Vμ) (implements eq. A.8 v0.7.0)
func (m *Memory) Read(address uint64, data []byte) error {
	// ☇ if min(x) mod 2^32 < 2^16
	if address < 1<<16 {
		return ErrPanicf("forbidden memory access")
	}
	var memoryData []byte
	access := Inaccessible
	if address >= m.stack.address && address+uint64(len(data)) <= m.stack.address+uint64(len(m.stack.data)) {
		memoryData = m.stack.data[address-m.stack.address : address-m.stack.address+uint64(len(data))]
		access = m.stack.access
	} else if address >= m.rw.address && address+uint64(len(data)) <= m.rw.address+uint64(len(m.rw.data)) {
		memoryData = m.rw.data[address-m.rw.address : address-m.rw.address+uint64(len(data))]
		access = m.rw.access
	} else if address >= m.ro.address && address+uint64(len(data)) <= m.ro.address+uint64(len(m.ro.data)) {
		memoryData = m.ro.data[address-m.ro.address : address-m.ro.address+uint64(len(data))]
		access = m.ro.access
	} else if address >= m.args.address && address+uint64(len(data)) <= m.args.address+uint64(len(m.args.data)) {
		memoryData = m.args.data[address-m.args.address : address-m.args.address+uint64(len(data))]
		access = m.args.access
		logd := make([]byte, len(data))
		copy(logd, memoryData)
	}

	// F × ZP ⌊ min(x) mod 2^32 ÷ ZP ⌋ (eq. A.9 v0.7.0)
	if access == Inaccessible {
		// find the minimum page that is not readable
		for i := address / PageSize; i <= (address+uint64(len(data)))/PageSize; i++ {
			access := m.GetAccess(i)
			if access == Inaccessible {
				return &ErrPageFault{Reason: "inaccessible memory", Address: i * PageSize}
			}
		}
		return ErrPanicf("inaccessible memory; unable to find the bad memory page")
	}
	copy(data, memoryData)
	return nil
}

// Write writes to the set of writeable indices (Vμ*) (implements eq. A.8 v0.7.0)
func (m *Memory) Write(address uint64, data []byte) error {
	// ☇ if min(x) mod 2^32 < 2^16
	if address < 1<<16 {
		return ErrPanicf("forbidden memory access")
	}

	var memoryData []byte
	access := Inaccessible
	if address >= m.stack.address && address+uint64(len(data)) <= m.stack.address+uint64(len(m.stack.data)) {
		memoryData = m.stack.data[address-m.stack.address : address-m.stack.address+uint64(len(data))]
		access = m.stack.access
	} else if address >= m.rw.address && address+uint64(len(data)) <= m.rw.address+uint64(len(m.rw.data)) {
		memoryData = m.rw.data[address-m.rw.address : address-m.rw.address+uint64(len(data))]
		access = m.rw.access
	} else if address >= m.ro.address && address+uint64(len(data)) <= m.ro.address+uint64(len(m.ro.data)) {
		memoryData = m.ro.data[address-m.ro.address : address-m.ro.address+uint64(len(data))]
		access = m.ro.access
	} else if address >= m.args.address && address+uint64(len(data)) <= m.args.address+uint64(len(m.args.data)) {
		memoryData = m.args.data[address-m.args.address : address-m.args.address+uint64(len(data))]
		access = m.args.access
	}

	// F × ZP ⌊ min(x) mod 2^32 ÷ ZP ⌋
	if access != ReadWrite {
		// find the minimum page that is not writeable
		for i := address / PageSize; i <= (address+uint64(len(data)))/PageSize; i++ {
			access := m.GetAccess(i)
			if access != ReadWrite { // return min(page) where the issue was found
				return &ErrPageFault{Reason: "memory at address is not writeable", Address: i * PageSize}
			}
		}
		return ErrPanicf("inaccessible memory; unable to find the bad memory page")
	}
	copy(memoryData, data)
	return nil
}

func (m *Memory) Sbrk(size uint64) (uint64, error) {
	if size == 0 {
		return m.currentHeapPointer, nil
	}

	result := m.currentHeapPointer

	nextPageBoundary := alignToPage(m.currentHeapPointer)
	newHeapPointer := m.currentHeapPointer + size

	if newHeapPointer > nextPageBoundary {
		finalBoundary := alignToPage(newHeapPointer)
		idxStart := nextPageBoundary / PageSize
		idxEnd := finalBoundary / PageSize
		pageCount := idxEnd - idxStart

		m.allocatePages(idxStart, pageCount)
	}

	// Advance the heap
	m.currentHeapPointer = newHeapPointer
	return result, nil
}

func (m *Memory) allocatePages(startPage uint64, count uint64) {
	required := (startPage + count) * PageSize
	if uint64(len(m.rw.data)) < required {
		// Grow rw_data to fit new allocation
		newData := make([]byte, required)
		copy(newData, m.rw.data)
		m.rw.data = newData
	}
}

// SetAccess updates the access mode
func (m *Memory) SetAccess(pageIndex uint64, access MemoryAccess) error {
	address := pageIndex * PageSize

	if address >= m.stack.address && address < m.stack.address+uint64(len(m.stack.data)) {
		m.stack.access = access
		return nil
	} else if address >= m.rw.address && address < m.rw.address+uint64(len(m.rw.data)) {
		m.rw.access = access
		return nil
	} else if address >= m.ro.address && address < m.ro.address+uint64(len(m.ro.data)) {
		m.ro.access = access
		return nil
	} else if address >= m.args.address && address < m.args.address+uint64(len(m.args.data)) {
		m.args.access = access
		return nil
	}

	return &ErrPageFault{Reason: "page out of valid range", Address: address}
}

func (m *Memory) GetAccess(pageIndex uint64) MemoryAccess {
	address := pageIndex * PageSize

	if address >= m.stack.address && address < m.stack.address+uint64(len(m.stack.data)) {
		return m.stack.access
	} else if address >= m.rw.address && address < m.rw.address+uint64(len(m.rw.data)) {
		return m.rw.access
	} else if address >= m.ro.address && address < m.ro.address+uint64(len(m.ro.data)) {
		return m.ro.access
	} else if address >= m.args.address && address < m.args.address+uint64(len(m.args.data)) {
		return m.args.access
	}

	return Inaccessible
}

type Registers [13]uint64

type Gas uint64

// HostCall the generic Ω function definition Ω⟨⟩X ≡ (N, NG, ⟦NR⟧13, M, X) → ({▸, ∎, ☇, ∞}, NG, ⟦NR⟧13, M, X) ∪ {F} × NR (eq. A.36 v0.7.0)
type HostCall[X any] func(hostCall uint64, gasCounter Gas, regs Registers, mem Memory, x X) (Gas, Registers, Memory, X, error)

type Mutator interface {
	Trap() error
	Fallthrough()

	LoadImm64(Reg, uint64)

	StoreImmU8(uint64, uint64) error
	StoreImmU16(uint64, uint64) error
	StoreImmU32(uint64, uint64) error
	StoreImmU64(uint64, uint64) error

	Jump(uint64) error

	JumpIndirect(Reg, uint64) error
	LoadImm(Reg, uint64)
	LoadU8(Reg, uint64) error
	LoadI8(Reg, uint64) error
	LoadU16(Reg, uint64) error
	LoadI16(Reg, uint64) error
	LoadU32(Reg, uint64) error
	LoadI32(Reg, uint64) error
	LoadU64(Reg, uint64) error
	StoreU8(Reg, uint64) error
	StoreU16(Reg, uint64) error
	StoreU32(Reg, uint64) error
	StoreU64(Reg, uint64) error

	StoreImmIndirectU8(Reg, uint64, uint64) error
	StoreImmIndirectU16(Reg, uint64, uint64) error
	StoreImmIndirectU32(Reg, uint64, uint64) error
	StoreImmIndirectU64(Reg, uint64, uint64) error

	LoadImmAndJump(Reg, uint64, uint64) error
	BranchEqImm(Reg, uint64, uint64) error
	BranchNotEqImm(Reg, uint64, uint64) error
	BranchLessUnsignedImm(Reg, uint64, uint64) error
	BranchLessOrEqualUnsignedImm(Reg, uint64, uint64) error
	BranchGreaterOrEqualUnsignedImm(Reg, uint64, uint64) error
	BranchGreaterUnsignedImm(Reg, uint64, uint64) error
	BranchLessSignedImm(Reg, uint64, uint64) error
	BranchLessOrEqualSignedImm(Reg, uint64, uint64) error
	BranchGreaterOrEqualSignedImm(Reg, uint64, uint64) error
	BranchGreaterSignedImm(Reg, uint64, uint64) error

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

	StoreIndirectU8(Reg, Reg, uint64) error
	StoreIndirectU16(Reg, Reg, uint64) error
	StoreIndirectU32(Reg, Reg, uint64) error
	StoreIndirectU64(Reg, Reg, uint64) error
	LoadIndirectU8(Reg, Reg, uint64) error
	LoadIndirectI8(Reg, Reg, uint64) error
	LoadIndirectU16(Reg, Reg, uint64) error
	LoadIndirectI16(Reg, Reg, uint64) error
	LoadIndirectU32(Reg, Reg, uint64) error
	LoadIndirectI32(Reg, Reg, uint64) error
	LoadIndirectU64(Reg, Reg, uint64) error
	AddImm32(Reg, Reg, uint64)
	AndImm(Reg, Reg, uint64)
	XorImm(Reg, Reg, uint64)
	OrImm(Reg, Reg, uint64)
	MulImm32(Reg, Reg, uint64)
	SetLessThanUnsignedImm(Reg, Reg, uint64)
	SetLessThanSignedImm(Reg, Reg, uint64)
	ShiftLogicalLeftImm32(Reg, Reg, uint64)
	ShiftLogicalRightImm32(Reg, Reg, uint64)
	ShiftArithmeticRightImm32(Reg, Reg, uint64)
	NegateAndAddImm32(Reg, Reg, uint64)
	SetGreaterThanUnsignedImm(Reg, Reg, uint64)
	SetGreaterThanSignedImm(Reg, Reg, uint64)
	ShiftLogicalLeftImmAlt32(Reg, Reg, uint64)
	ShiftLogicalRightImmAlt32(Reg, Reg, uint64)
	ShiftArithmeticRightImmAlt32(Reg, Reg, uint64)
	CmovIfZeroImm(Reg, Reg, uint64)
	CmovIfNotZeroImm(Reg, Reg, uint64)
	AddImm64(Reg, Reg, uint64)
	MulImm64(Reg, Reg, uint64)
	ShiftLogicalLeftImm64(Reg, Reg, uint64)
	ShiftLogicalRightImm64(Reg, Reg, uint64)
	ShiftArithmeticRightImm64(Reg, Reg, uint64)
	NegateAndAddImm64(Reg, Reg, uint64)
	ShiftLogicalLeftImmAlt64(Reg, Reg, uint64)
	ShiftLogicalRightImmAlt64(Reg, Reg, uint64)
	ShiftArithmeticRightImmAlt64(Reg, Reg, uint64)
	RotateRight64Imm(Reg, Reg, uint64)
	RotateRight64ImmAlt(Reg, Reg, uint64)
	RotateRight32Imm(Reg, Reg, uint64)
	RotateRight32ImmAlt(Reg, Reg, uint64)

	BranchEq(Reg, Reg, uint64) error
	BranchNotEq(Reg, Reg, uint64) error
	BranchLessUnsigned(Reg, Reg, uint64) error
	BranchLessSigned(Reg, Reg, uint64) error
	BranchGreaterOrEqualUnsigned(Reg, Reg, uint64) error
	BranchGreaterOrEqualSigned(Reg, Reg, uint64) error

	LoadImmAndJumpIndirect(Reg, Reg, uint64, uint64) error

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

// AccumulateContext B.7 (v0.6.7)
type AccumulateContext struct {
	ServiceId         block.ServiceId            // s
	AccumulationState state.AccumulationState    // u
	NewServiceId      block.ServiceId            // i
	DeferredTransfers []service.DeferredTransfer // t
	AccumulationHash  *crypto.Hash               // y
	ProvidedPreimages []ProvidedPreimage         // p
}

func (s *AccumulateContext) Clone() AccumulateContext {
	cc := AccumulateContext{
		ServiceId:         s.ServiceId,
		AccumulationState: s.AccumulationState.Clone(),
		NewServiceId:      s.NewServiceId,
		DeferredTransfers: make([]service.DeferredTransfer, len(s.DeferredTransfers)),
		ProvidedPreimages: make([]ProvidedPreimage, len(s.ProvidedPreimages)),
	}
	if s.AccumulationHash != nil {
		cc.AccumulationHash = new(crypto.Hash)
		*cc.AccumulationHash = *s.AccumulationHash
	}
	for i, dt := range s.DeferredTransfers {
		cc.DeferredTransfers[i] = service.DeferredTransfer{
			SenderServiceIndex:   dt.SenderServiceIndex,
			ReceiverServiceIndex: dt.ReceiverServiceIndex,
			Balance:              dt.Balance,
			Memo:                 dt.Memo,
			GasLimit:             dt.GasLimit,
		}
	}

	for i, p := range s.ProvidedPreimages {
		cc.ProvidedPreimages[i] = ProvidedPreimage{
			ServiceId: p.ServiceId,
			Data:      bytes.Clone(p.Data),
		}
	}
	return cc
}

type ProvidedPreimage struct {
	ServiceId block.ServiceId
	Data      []byte
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
	InstructionCounter uint64 //i  instruction counter
}

type RefineContextPair struct {
	IntegratedPVMMap map[uint64]IntegratedPVM //m
	Segments         []work.Segment           //e
}
