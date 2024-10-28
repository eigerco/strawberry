// Constants, memory map and align to next page implementation used as reference are taken from:
// https://github.com/koute/polkavm/blob/e905e981c756bc9a27a5780341f24c7bdabae568/crates/polkavm-common/src/abi.rs
// We are using the same ABI as koute's PVM implementation in order for us to be able to
// run and test the programs designed specifically for koute's PVM implementation.
// However, this is the only thing that these two PVMs have in common.

package polkavm

import (
	"errors"
	"fmt"
	"math"
)

const (
	AddressSpaceSize      = 0x100000000                      // 2^32
	VmMinPageSize         = 0x1000                           // The minimum page size of the VM
	VmMaxPageSize         = 0x10000                          // The maximum page size of the VM.
	VmAddressReturnToHost = 0xffff0000                       // The address which, when jumped to, will return to the host.
	VmAddressSpaceTop     = AddressSpaceSize - VmMaxPageSize // The address at which the program's stackData starts inside of the VM.
	VmAddressSpaceBottom  = VmMaxPageSize                    // The bottom of the accessible address space inside the VM (ZQ?)
)

var (
	ErrPageValueTooLarge     = errors.New("page value too large")
	ErrPageSizeNotPowerOfTwo = errors.New("page size is not a power of two")
)

func NewMemoryMap(pageSize, roDataSize, rwDataSize, stackSize, argsDataSize uint) (*MemoryMap, error) {
	if pageSize < VmMinPageSize {
		return nil, fmt.Errorf("invalid page size: page size is too small")
	}

	if pageSize > VmMaxPageSize {
		return nil, fmt.Errorf("invalid page size: page size is too big")
	}
	roDataAddressSpace, err := AlignToNextPage(VmMaxPageSize, roDataSize)
	if err != nil {
		return nil, fmt.Errorf("failed to instantiate memory map ro data address space: %w", err)
	}

	roDataSize, err = AlignToNextPage(pageSize, roDataSize)
	if err != nil {
		return nil, fmt.Errorf("failed to instantiate memory map ro data size: %w", err)
	}

	rwDataAddressSpace, err := AlignToNextPage(VmMaxPageSize, rwDataSize)
	if err != nil {
		return nil, fmt.Errorf("failed to instantiate memory map rw data address space: %w", err)
	}

	originalRwDataSize := rwDataSize
	rwDataSize, err = AlignToNextPage(pageSize, rwDataSize)
	if err != nil {
		return nil, fmt.Errorf("failed to instantiate memory map rw data size: %w", err)
	}

	stackAddressSpace, err := AlignToNextPage(VmMaxPageSize, stackSize)
	if err != nil {
		return nil, fmt.Errorf("failed to instantiate memory map stackData address space: %w", err)
	}

	stackSize, err = AlignToNextPage(pageSize, stackSize)
	if err != nil {
		return nil, fmt.Errorf("failed to instantiate memory map stackData size: %w", err)
	}
	argsDataAddressSpace, err := AlignToNextPage(VmMaxPageSize, argsDataSize)
	if err != nil {
		return nil, fmt.Errorf("the size of the arguments data is too big %w", err)
	}

	argsDataSize, err = AlignToNextPage(pageSize, argsDataSize)
	if err != nil {
		return nil, fmt.Errorf("the size of the arguments data is too big %w", err)
	}
	var addressLow uint
	addressLow += VmAddressSpaceBottom
	addressLow += roDataAddressSpace
	addressLow += VmMaxPageSize

	rwDataAddress := addressLow
	heapBase := addressLow + originalRwDataSize
	addressLow += rwDataAddressSpace
	heapSlack := addressLow - heapBase
	addressLow += VmMaxPageSize

	var addressHigh uint = VmAddressSpaceTop
	addressHigh -= argsDataAddressSpace
	argsDataAddress := addressHigh
	addressHigh -= VmMaxPageSize
	stackAddressHigh := addressHigh
	addressHigh -= stackAddressSpace

	if addressLow > addressHigh {
		return nil, fmt.Errorf("maximum memory size exceeded")
	}

	maxHeapSize := addressHigh - addressLow + heapSlack

	return &MemoryMap{
		PageSize:         uint32(pageSize),
		RODataSize:       uint32(roDataSize),
		RWDataAddress:    uint32(rwDataAddress),
		RWDataSize:       uint32(rwDataSize),
		StackAddressHigh: uint32(stackAddressHigh),
		StackAddressLow:  uint32(stackAddressHigh - stackSize),
		StackSize:        uint32(stackSize),
		HeapBase:         uint32(heapBase),
		MaxHeapSize:      uint32(maxHeapSize),
		RODataAddress:    VmMaxPageSize,
		ArgsDataAddress:  uint32(argsDataAddress),
		ArgsDataSize:     uint32(argsDataSize),
	}, nil
}

type MemoryMap struct {
	PageSize         uint32
	RODataSize       uint32
	RWDataSize       uint32
	StackSize        uint32
	HeapBase         uint32
	MaxHeapSize      uint32
	StackAddressHigh uint32
	RODataAddress    uint32
	StackAddressLow  uint32
	RWDataAddress    uint32
	ArgsDataAddress  uint32
	ArgsDataSize     uint32
}

func (mm MemoryMap) NewMemory(rwData, roData, argsData []byte) Memory {
	m := Memory{
		data: make([]byte, 1<<32),
		access: []accessRanges{
			{mm.ArgsDataAddress, mm.ArgsDataAddress + mm.ArgsDataSize, ReadOnly},
			{mm.StackAddressLow, mm.StackAddressLow + mm.StackSize, ReadWrite},
			{mm.RWDataAddress, mm.RWDataAddress + mm.RWDataSize, ReadWrite},
			{mm.RODataAddress, mm.RODataAddress + mm.RODataSize, ReadOnly},
		},
	}

	copy(m.data[mm.RWDataAddress:mm.RWDataAddress+mm.RWDataSize], rwData)
	copy(m.data[mm.RODataAddress:mm.RODataAddress+mm.RODataSize], roData)
	copy(m.data[mm.ArgsDataAddress:mm.ArgsDataAddress+mm.ArgsDataSize], argsData)
	return m
}

func AlignToNextPage(pageSize uint, value uint) (uint, error) {
	if !(pageSize != 0 && (pageSize&(pageSize-1)) == 0) {
		return 0, ErrPageSizeNotPowerOfTwo
	}
	if value&(pageSize-1) == 0 {
		return value, nil
	} else {
		if value <= math.MaxUint-pageSize {
			return (value + pageSize) & ^(pageSize - 1), nil
		}
	}
	return 0, ErrPageValueTooLarge
}
