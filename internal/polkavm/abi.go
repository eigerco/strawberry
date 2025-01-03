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
	AddressSpaceSize      = 0x100000000                           // 2^32
	VmMaxPageSize         = 0x10000                               // The maximum page size of the VM.
	VMPageSize            = uint32(1 << 12)                       // ZP: 4096 (2^12) The pvm memory page size.
	VmAddressReturnToHost = 0xffff0000                            // The address which, when jumped to, will return to the host.
	VmAddressSpaceTop     = AddressSpaceSize - VmMaxPageSize      // The address at which the program's stackData starts inside of the VM.
	VmAddressSpaceBottom  = VmMaxPageSize                         // The bottom of the accessible address space inside the VM (ZQ?)
	VMMaxPageIndex        = AddressSpaceSize / uint64(VMPageSize) // 2^32 / ZP = 1 << 20
)

var (
	ErrPageValueTooLarge = errors.New("page value too large")
)

func NewMemoryMap(roDataSize, rwDataSize, stackSize, argsDataSize uint32) (*MemoryMap, error) {
	roDataAddressSpace, err := AlignToNextPage(roDataSize)
	if err != nil {
		return nil, fmt.Errorf("failed to instantiate memory map ro data address space: %w", err)
	}

	roDataSize, err = AlignToNextPage(roDataSize)
	if err != nil {
		return nil, fmt.Errorf("failed to instantiate memory map ro data size: %w", err)
	}

	rwDataAddressSpace, err := AlignToNextPage(rwDataSize)
	if err != nil {
		return nil, fmt.Errorf("failed to instantiate memory map rw data address space: %w", err)
	}

	originalRwDataSize := rwDataSize
	rwDataSize, err = AlignToNextPage(rwDataSize)
	if err != nil {
		return nil, fmt.Errorf("failed to instantiate memory map rw data size: %w", err)
	}

	stackAddressSpace, err := AlignToNextPage(stackSize)
	if err != nil {
		return nil, fmt.Errorf("failed to instantiate memory map stackData address space: %w", err)
	}

	stackSize, err = AlignToNextPage(stackSize)
	if err != nil {
		return nil, fmt.Errorf("failed to instantiate memory map stackData size: %w", err)
	}
	argsDataAddressSpace, err := AlignToNextPage(argsDataSize)
	if err != nil {
		return nil, fmt.Errorf("the size of the arguments data is too big %w", err)
	}

	argsDataSize, err = AlignToNextPage(argsDataSize)
	if err != nil {
		return nil, fmt.Errorf("the size of the arguments data is too big %w", err)
	}
	var addressLow uint32
	addressLow += VmAddressSpaceBottom
	addressLow += roDataAddressSpace
	addressLow += VmMaxPageSize

	rwDataAddress := addressLow
	heapBase := addressLow + originalRwDataSize
	addressLow += rwDataAddressSpace
	heapSlack := addressLow - heapBase
	addressLow += VmMaxPageSize

	var addressHigh uint32 = VmAddressSpaceTop
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
		RODataSize:       roDataSize,
		RWDataAddress:    rwDataAddress,
		RWDataSize:       rwDataSize,
		StackAddressHigh: stackAddressHigh,
		StackAddressLow:  stackAddressHigh - stackSize,
		StackSize:        stackSize,
		HeapBase:         heapBase,
		MaxHeapSize:      maxHeapSize,
		RODataAddress:    VmMaxPageSize,
		ArgsDataAddress:  argsDataAddress,
		ArgsDataSize:     argsDataSize,
	}, nil
}

type MemoryMap struct {
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
		data: []*memorySegment{
			{mm.ArgsDataAddress, mm.ArgsDataAddress + mm.ArgsDataSize, ReadOnly, copySized(argsData, mm.ArgsDataSize)},
			{mm.StackAddressLow, mm.StackAddressLow + mm.StackSize, ReadWrite, make([]byte, mm.StackSize)},
			{mm.RWDataAddress, mm.RWDataAddress + mm.RWDataSize, ReadWrite, copySized(rwData, mm.RWDataSize)},
			{mm.RODataAddress, mm.RODataAddress + mm.RODataSize, ReadOnly, copySized(roData, mm.RODataSize)},
		},
	}
	return m
}

func copySized(data []byte, size uint32) []byte {
	dst := make([]byte, size)
	copy(dst, data)
	return dst
}

func AlignToNextPage(value uint32) (uint32, error) {
	if value&(VMPageSize-1) == 0 {
		return value, nil
	}
	if value <= (math.MaxUint32 - VmMaxPageSize) {
		return (value + VMPageSize) & ^(VMPageSize - 1), nil
	}

	return 0, ErrPageValueTooLarge
}
