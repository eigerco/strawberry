package interpreter

import (
	"fmt"

	"github.com/eigerco/strawberry/internal/polkavm"
)

type TrapError struct {
	Err error
}

func (t TrapError) Error() string {
	return fmt.Sprintf("trap error: %s", t.Err)
}

type ExecutionError struct {
	Err error
}

func (e ExecutionError) Error() string {
	return fmt.Sprintf("execution error: %s", e.Err)
}

type callFunc func(instance *instance) error

type instance struct {
	memory              *memory
	regs                map[polkavm.Reg]uint32
	instructionOffset   uint32
	instructionLength   uint32
	returnToHost        bool
	cycleCounter        uint64
	offsetForBasicBlock map[uint32]int
	instructions        []polkavm.Instruction
	instructionCounter  int
	gasRemaining        int64
}

func (v *instance) deductGas(cost int64) {
	if cost > v.gasRemaining {
		v.gasRemaining = 0
	} else {
		v.gasRemaining -= cost
	}
}

type memory struct {
	rwData   []byte
	stack    []byte
	heapSize uint32
}

func newBasicMemory(memoryMap *memoryMap, rwData []byte) *memory {
	m := &memory{
		rwData: make([]byte, memoryMap.rwDataSize),
		stack:  make([]byte, memoryMap.stackSize),
	}
	copy(m.rwData, rwData)
	return m
}

func (m *memory) getMemorySlice(program polkavm.Program, memoryMap memoryMap, address uint32, length int) ([]byte, error) {
	var start uint32
	var memorySlice []byte
	if address >= memoryMap.stackAddressLow {
		start, memorySlice = memoryMap.stackAddressLow, m.stack
	} else if address >= memoryMap.rwDataAddress {
		start, memorySlice = memoryMap.rwDataAddress, m.rwData
	} else if address >= memoryMap.roDataAddress {
		start, memorySlice = memoryMap.roDataAddress, program.ROData
	} else {
		return nil, nil
	}

	offset := int(address - start)
	if offset+length > len(memorySlice) {
		return nil, fmt.Errorf("memory slice out of range, address %d, length: %d", address, length)
	}
	return memorySlice[offset : offset+length], nil
}

func (m *memory) getMemorySlicePointer(memoryMap memoryMap, address uint32, length int) (*[]byte, error) {
	var start uint32
	var memorySlice []byte
	if address >= memoryMap.stackAddressLow {
		start, memorySlice = memoryMap.stackAddressLow, m.stack
	} else if address >= memoryMap.rwDataAddress {
		start, memorySlice = memoryMap.rwDataAddress, m.rwData
	} else {
		return nil, nil
	}

	offset := int(address - start)
	if offset+length > len(memorySlice) {
		return nil, fmt.Errorf("memory slice out of range, address %d, length: %d", address, length)
	}
	slice := memorySlice[offset : offset+length]
	return &slice, nil
}

func (m *memory) sbrk(memoryMap memoryMap, size uint32) (uint32, error) {
	newHeapSize := m.heapSize + size
	if newHeapSize > memoryMap.maxHeapSize {
		return 0, fmt.Errorf("max heap size exceeded")
	}

	m.heapSize = newHeapSize
	heapTop := memoryMap.heapBase + newHeapSize
	if heapTop > memoryMap.rwDataAddress+uint32(len(m.rwData)) {
		nextPage, err := alignToNextPageInt(int(memoryMap.pageSize), int(heapTop))
		if err != nil {
			return 0, err
		}
		newSize := nextPage - int(memoryMap.rwDataAddress)
		rwData := m.rwData
		m.rwData = make([]byte, newSize)
		copy(m.rwData, rwData)
	}

	return heapTop, nil
}
