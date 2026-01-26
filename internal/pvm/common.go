package pvm

import (
	"bytes"

	"github.com/eigerco/strawberry/internal/block"
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/safemath"
	"github.com/eigerco/strawberry/internal/service"
	"github.com/eigerco/strawberry/internal/state"
	"github.com/eigerco/strawberry/internal/work"
)

var ErrForbiddenMemoryAccess = ErrPanicf("forbidden memory access")

type MemoryAccess int

const (
	Inaccessible MemoryAccess = iota // ∅ (Inaccessible)
	ReadOnly                         // R (Read-Only)
	ReadWrite                        // W (Read-Write)
)

// Memory M ≡ (v ∈ B_(2^32), a ∈ ⟦{W, R, ∅}⟧p) (eq. 4.24 v0.7.2)
// for practical reasons we define each memory segment separately
// so we don't have to allocate [2^32]byte unnecessarily
type Memory struct {
	ro                 memorySegment
	rw                 memorySegment
	stack              memorySegment
	args               memorySegment
	currentHeapPointer uint32
}

type memorySegment struct {
	address uint32
	end     uint32
	data    []byte
	access  MemoryAccess
}

// Read reads from the set of readable indices (Vμ) (implements eq. A.7 v0.7.2)
func (m *Memory) Read(address uint32, data []byte) error {
	if len(data) == 0 {
		return nil
	}

	// ☇ if min(x) mod 2^32 < 2^16
	if address < 1<<16 {
		return ErrForbiddenMemoryAccess
	}
	end, ok := safemath.Add(address, uint32(len(data)))
	if !ok {
		return ErrPanicf("inaccessible memory; address overflow")
	}
	var memoryData []byte
	access := Inaccessible

	if address >= m.stack.address && end <= m.stack.end {
		memoryData = m.stack.data[address-m.stack.address : end-m.stack.address]
		access = m.stack.access
	} else if address >= m.rw.address && end <= m.currentHeapPointer {
		memoryData = m.rw.data[address-m.rw.address : end-m.rw.address]
		access = m.rw.access
	} else if address >= m.ro.address && end <= m.ro.end {
		memoryData = m.ro.data[address-m.ro.address : end-m.ro.address]
		access = m.ro.access
	} else if address >= m.args.address && end <= m.args.end {
		memoryData = m.args.data[address-m.args.address : end-m.args.address]
		access = m.args.access
	}

	// F × ZP ⌊ min(x) mod 2^32 ÷ ZP ⌋ (eq. A.8 v0.7.2)
	if access == Inaccessible {
		// find the minimum page that is not readable
		for i := address / PageSize; i <= end/PageSize; i++ {
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

// Write writes to the set of writeable indices (Vμ*) (implements eq. A.7 v0.7.2)
func (m *Memory) Write(address uint32, data []byte) error {
	if len(data) == 0 {
		return nil
	}

	// ☇ if min(x) mod 2^32 < 2^16
	if address < 1<<16 {
		return ErrForbiddenMemoryAccess
	}
	end, ok := safemath.Add(address, uint32(len(data)))
	if !ok {
		return ErrPanicf("inaccessible memory; address overflow")
	}
	var memoryData []byte
	access := Inaccessible
	if address >= m.stack.address && end <= m.stack.end {
		memoryData = m.stack.data[address-m.stack.address : end-m.stack.address]
		access = m.stack.access
	} else if address >= m.rw.address && end <= m.currentHeapPointer {
		memoryData = m.rw.data[address-m.rw.address : end-m.rw.address]
		access = m.rw.access
	} else if address >= m.ro.address && end <= m.ro.end {
		memoryData = m.ro.data[address-m.ro.address : end-m.ro.address]
		access = m.ro.access
	} else if address >= m.args.address && end <= m.args.end {
		memoryData = m.args.data[address-m.args.address : end-m.args.address]
		access = m.args.access
	}

	// F × ZP ⌊ min(x) mod 2^32 ÷ ZP ⌋
	if access != ReadWrite {
		// find the minimum page that is not writeable
		for i := address / PageSize; i <= end/PageSize; i++ {
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

func (m *Memory) Sbrk(size uint32) (uint32, error) {
	if size == 0 {
		return m.currentHeapPointer, nil
	}

	result := m.currentHeapPointer

	nextPageBoundary, err := roundUpToPage(m.currentHeapPointer)
	if err != nil {
		return 0, ErrPanicf("unable to find the next page boundary: %s", err)
	}
	newHeapPointer := m.currentHeapPointer + size

	if newHeapPointer > nextPageBoundary {
		finalBoundary, err := roundUpToPage(newHeapPointer)
		if err != nil {
			return 0, ErrPanicf("unable to find the next page boundary: %s", err)
		}
		idxStart := nextPageBoundary / PageSize
		idxEnd := finalBoundary / PageSize
		pageCount := idxEnd - idxStart

		m.allocatePages(idxStart, pageCount)
	}

	// Advance the heap
	m.currentHeapPointer = newHeapPointer
	return result, nil
}

func (m *Memory) allocatePages(startPage uint32, count uint32) {
	required := (startPage + count) * PageSize
	if uint32(len(m.rw.data)) < required {
		// Grow rw_data to fit new allocation
		newData := make([]byte, required)
		copy(newData, m.rw.data)
		m.rw.data = newData
	}
}

// SetAccess updates the access mode
func (m *Memory) SetAccess(pageIndex uint32, access MemoryAccess) error {
	address := pageIndex * PageSize

	if address >= m.stack.address && address < m.stack.end {
		m.stack.access = access
		return nil
	} else if address >= m.rw.address && address < m.rw.end {
		m.rw.access = access
		return nil
	} else if address >= m.ro.address && address < m.ro.end {
		m.ro.access = access
		return nil
	} else if address >= m.args.address && address < m.args.end {
		m.args.access = access
		return nil
	}

	return &ErrPageFault{Reason: "page out of valid range", Address: address}
}

func (m *Memory) GetAccess(pageIndex uint32) MemoryAccess {
	address := pageIndex * PageSize

	if address >= m.stack.address && address < m.stack.end {
		return m.stack.access
	} else if address >= m.rw.address && address < m.rw.end {
		return m.rw.access
	} else if address >= m.ro.address && address < m.ro.end {
		return m.ro.access
	} else if address >= m.args.address && address < m.args.end {
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
