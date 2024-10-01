// Constants, memory map and align to next page implementation used as reference are taken from:
// https://github.com/koute/polkavm/blob/e905e981c756bc9a27a5780341f24c7bdabae568/crates/polkavm-common/src/abi.rs
// We are using the same ABI as koute's PVM implementation in order for us to be able to
// run and test the programs designed specifically for koute's PVM implementation.
// However, this is the only thing that these two PVMs have in common.

package interpreter

import (
	"errors"
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

var (
	ErrPageValueTooLarge     = errors.New("page value too large")
	ErrPageSizeNotPowerOfTwo = errors.New("page size is not a power of two")
)

func newMemoryMap(pageSize uint32, p *polkavm.Program) (*memoryMap, error) {
	if pageSize < VmMinPageSize {
		return nil, fmt.Errorf("invalid page size: page size is too small")
	}

	if pageSize > VmMaxPageSize {
		return nil, fmt.Errorf("invalid page size: page size is too big")
	}
	roDataAddressSpace, err := alignToNextPageUint64(uint64(VmMaxPageSize), uint64(p.RODataSize))
	if err != nil {
		return nil, fmt.Errorf("failed to instantiate memory map ro data address space: %w", err)
	}

	roDataSize, err := alignToNextPageUint32(pageSize, p.RODataSize)
	if err != nil {
		return nil, fmt.Errorf("failed to instantiate memory map ro data size: %w", err)
	}

	rwDataAddressSpace, err := alignToNextPageUint64(uint64(VmMaxPageSize), uint64(p.RWDataSize))
	if err != nil {
		return nil, fmt.Errorf("failed to instantiate memory map rw data address space: %w", err)
	}

	originalRwDataSize := p.RWDataSize
	rwDataSize, err := alignToNextPageUint32(pageSize, p.RWDataSize)
	if err != nil {
		return nil, fmt.Errorf("failed to instantiate memory map rw data size: %w", err)
	}

	stackAddressSpace, err := alignToNextPageUint64(uint64(VmMaxPageSize), uint64(p.StackSize))
	if err != nil {
		return nil, fmt.Errorf("failed to instantiate memory map stack address space: %w", err)
	}

	stackSize, err := alignToNextPageUint32(pageSize, p.StackSize)
	if err != nil {
		return nil, fmt.Errorf("failed to instantiate memory map stack size: %w", err)
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
	rwDataAddressOffset, err := alignToNextPageUint32(VmMaxPageSize, VmMaxPageSize+roDataSize)
	if err != nil {
		return nil, err
	}
	return &memoryMap{
		pageSize:         pageSize,
		roDataSize:       roDataSize,
		rwDataSize:       rwDataSize,
		stackSize:        stackSize,
		heapBase:         uint32(heapBase),
		maxHeapSize:      uint32(maxHeapSize),
		stackAddressHigh: VmAddrUserStackHigh,
		roDataAddress:    VmMaxPageSize,
		stackAddressLow:  VmAddrUserStackHigh - stackSize,
		rwDataAddress:    rwDataAddressOffset + VmMaxPageSize,
	}, nil
}

type memoryMap struct {
	pageSize         uint32
	roDataSize       uint32
	rwDataSize       uint32
	stackSize        uint32
	heapBase         uint32
	maxHeapSize      uint32
	stackAddressHigh uint32
	roDataAddress    uint32
	stackAddressLow  uint32
	rwDataAddress    uint32
}

func alignToNextPageInt(pageSize int, value int) (int, error) {
	if !(pageSize != 0 && (pageSize&(pageSize-1)) == 0) {
		return 0, ErrPageSizeNotPowerOfTwo
	}
	if value&(pageSize-1) == 0 {
		return value, nil
	} else {
		if value <= math.MaxInt-pageSize {
			return (value + pageSize) & ^(pageSize - 1), nil
		}
	}
	return 0, ErrPageValueTooLarge
}

func alignToNextPageUint32(pageSize uint32, value uint32) (uint32, error) {
	if !(pageSize != 0 && (pageSize&(pageSize-1)) == 0) {
		return 0, ErrPageSizeNotPowerOfTwo
	}
	if value&(pageSize-1) == 0 {
		return value, nil
	} else {
		if value <= math.MaxUint32-pageSize {
			return (value + pageSize) & ^(pageSize - 1), nil
		}
	}
	return 0, ErrPageValueTooLarge
}

func alignToNextPageUint64(pageSize uint64, value uint64) (uint64, error) {
	if !(pageSize != 0 && (pageSize&(pageSize-1)) == 0) {
		return 0, ErrPageSizeNotPowerOfTwo
	}
	if value&(pageSize-1) == 0 {
		return value, nil
	} else if value <= math.MaxUint64-pageSize {
		return (value + pageSize) & ^(pageSize - 1), nil
	}
	return 0, ErrPageValueTooLarge
}
