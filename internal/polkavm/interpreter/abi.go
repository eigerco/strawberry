// Constants, memory map and align to next page implementation used as reference are taken from:
// https://github.com/koute/polkavm/blob/e905e981c756bc9a27a5780341f24c7bdabae568/crates/polkavm-common/src/abi.rs
// We are using the same ABI as koute's PVM implementation in order for us to be able to
// run and test the programs designed specifically for koute's PVM implementation.
// However, this is the only thing that these two PVMs have in common.

package interpreter

import (
	"fmt"
	"math"

	"github.com/eigerco/strawberry/internal/polkavm"
)

const (
	AddressSpaceSize    uint64 = 0x100000000
	VmMinPageSize       uint32 = 0x1000                                           // The minimum page size of the VM
	VmMaxPageSize       uint32 = 0x10000                                          // The maximum page size of the VM.
	VmAddrReturnToHost  uint32 = 0xffff0000                                       // The address which, when jumped to, will return to the host.
	VmAddrUserStackHigh uint32 = uint32(AddressSpaceSize - uint64(VmMaxPageSize)) // The address at which the program's stack starts inside of the VM.
)

func newMemoryMap(pageSize uint32, p *polkavm.Program) (*memoryMap, error) {
	if pageSize < VmMinPageSize {
		return nil, fmt.Errorf("invalid page size: page size is too small")
	}

	if pageSize > VmMaxPageSize {
		return nil, fmt.Errorf("invalid page size: page size is too big")
	}
	roDataAddressSpace, ok := alignToNextPageUint64(uint64(VmMaxPageSize), uint64(p.RODataSize))
	if !ok {
		return nil, fmt.Errorf("the size of read-only data is too big")
	}

	roDataSize, ok := alignToNextPageUint32(pageSize, p.RODataSize)
	if !ok {
		return nil, fmt.Errorf("the size of read-only data is too big")
	}

	rwDataAddressSpace, ok := alignToNextPageUint64(uint64(VmMaxPageSize), uint64(p.RWDataSize))
	if !ok {
		return nil, fmt.Errorf("the size of read-write data is too big")
	}

	originalRwDataSize := p.RWDataSize
	rwDataSize, ok := alignToNextPageUint32(pageSize, p.RWDataSize)
	if !ok {
		return nil, fmt.Errorf("the size of read-write data is too big")
	}

	stackAddressSpace, ok := alignToNextPageUint64(uint64(VmMaxPageSize), uint64(p.StackSize))
	if !ok {
		return nil, fmt.Errorf("the size of the stack is too big")
	}

	stackSize, ok := alignToNextPageUint32(pageSize, p.StackSize)
	if !ok {
		return nil, fmt.Errorf("the size of the stack is too big")
	}
	var addressLow uint64
	addressLow += uint64(VmMaxPageSize)
	addressLow += roDataAddressSpace
	addressLow += uint64(VmMaxPageSize)

	heapBase := addressLow + uint64(originalRwDataSize)
	addressLow += rwDataAddressSpace
	heapSlack := addressLow - heapBase
	addressLow += uint64(VmMaxPageSize)

	addressHigh := uint64(VmAddrUserStackHigh)
	addressHigh -= stackAddressSpace

	if addressLow > addressHigh {
		return nil, fmt.Errorf("maximum memory size exceeded")
	}

	maxHeapSize := addressHigh - addressLow + heapSlack

	return &memoryMap{
		pageSize:    pageSize,
		roDataSize:  roDataSize,
		rwDataSize:  rwDataSize,
		stackSize:   stackSize,
		heapBase:    uint32(heapBase),
		maxHeapSize: uint32(maxHeapSize),
	}, nil
}

type memoryMap struct {
	pageSize    uint32
	roDataSize  uint32
	rwDataSize  uint32
	stackSize   uint32
	heapBase    uint32
	maxHeapSize uint32
}

func (m *memoryMap) stackAddressHigh() uint32 { return VmAddrUserStackHigh }
func (m *memoryMap) roDataAddress() uint32    { return VmMaxPageSize }
func (m *memoryMap) stackAddressLow() uint32  { return m.stackAddressHigh() - m.stackSize }
func (m *memoryMap) rwDataAddress() uint32 {
	offset, ok := alignToNextPageUint32(VmMaxPageSize, m.roDataAddress()+m.roDataSize)
	if !ok {
		panic("unreachable")
	}
	return offset + VmMaxPageSize
}

func alignToNextPageInt(pageSize int, value int) (int, bool) {
	if !(pageSize != 0 && (pageSize&(pageSize-1)) == 0) {
		panic("page size is not a power of two")
	}
	if value&(pageSize-1) == 0 {
		return value, true
	} else {
		if value <= math.MaxInt-pageSize {
			return (value + pageSize) & ^(pageSize - 1), true
		}
	}
	return 0, false
}

func alignToNextPageUint32(pageSize uint32, value uint32) (uint32, bool) {
	if !(pageSize != 0 && (pageSize&(pageSize-1)) == 0) {
		panic("page size is not a power of two")
	}
	if value&(pageSize-1) == 0 {
		return value, true
	} else {
		if value <= math.MaxUint32-pageSize {
			return (value + pageSize) & ^(pageSize - 1), true
		}
	}
	return 0, false
}

func alignToNextPageUint64(pageSize uint64, value uint64) (uint64, bool) {
	if !(pageSize != 0 && (pageSize&(pageSize-1)) == 0) {
		panic("page size is not a power of two")
	}
	if value&(pageSize-1) == 0 {
		return value, true
	} else if value <= math.MaxUint64-pageSize {
		return (value + pageSize) & ^(pageSize - 1), true
	}
	return 0, false
}
