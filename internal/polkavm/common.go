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

// Gas the set of signed gas values ZG ≡ Z_−2^63...2^63 (eq. 4.23 v0.7.2)
type Gas int64

// UGas the set of unsigned gas values NG ≡ N_2^64 (eq. 4.23 v0.7.2)
type UGas uint64

// HostCall the generic Ω function definition Ω⟨X⟩ ≡ (N, NG, ⟦NR⟧13, M, X) → ({ ▸, ∎, ☇, ∞ }, NG, ⟦NR⟧13, M, X) (eq. A.36 v0.7.2)
type HostCall[X any] func(hostCall uint64, gasCounter Gas, regs Registers, mem Memory, x X) (Gas, Registers, Memory, X, error)

// AccumulateContext L ≡ (s ∈ NS, e ∈ S, i ∈ NS, t ∈ ⟦X⟧, y ∈ H?, p ∈ {( NS, B )}) (eq. B.7 v0.7.2)
type AccumulateContext struct {
	ServiceId         block.ServiceId            // s
	AccumulationState state.AccumulationState    // e
	NewServiceId      block.ServiceId            // i
	DeferredTransfers []service.DeferredTransfer // t
	AccumulationHash  *crypto.Hash               // y
	ProvidedPreimages []block.Preimage           // p
}

func (s *AccumulateContext) Clone() AccumulateContext {
	cc := AccumulateContext{
		ServiceId:         s.ServiceId,
		AccumulationState: s.AccumulationState.Clone(),
		NewServiceId:      s.NewServiceId,
		DeferredTransfers: make([]service.DeferredTransfer, len(s.DeferredTransfers)),
		ProvidedPreimages: make([]block.Preimage, len(s.ProvidedPreimages)),
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
		cc.ProvidedPreimages[i] = block.Preimage{
			ServiceIndex: p.ServiceIndex,
			Data:         bytes.Clone(p.Data),
		}
	}
	return cc
}

// ServiceAccount ∀x ∈ L ∶ xs ≡ (x_e)d[x_s] (eq. B.8 v0.7.2)
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
