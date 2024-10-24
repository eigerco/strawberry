package interpreter

import (
	"fmt"

	"github.com/eigerco/strawberry/internal/polkavm"
)

func NewMemory(memoryMap *polkavm.MemoryMap, rwData, roData, argsData []byte) *Memory {
	m := &Memory{
		roData:   make([]byte, memoryMap.RODataSize),
		rwData:   make([]byte, memoryMap.RWDataSize),
		argsData: make([]byte, memoryMap.ArgsDataSize),
		stack:    make([]byte, memoryMap.StackSize),
	}
	copy(m.rwData, rwData)
	copy(m.roData, roData)
	copy(m.argsData, argsData)
	return m
}

// Memory with it's two methods get and set corresponds to formula (264: v0.4.3)
type Memory struct {
	rwData   []byte
	roData   []byte
	argsData []byte
	stack    []byte
	heapSize uint32
}

func (m *Memory) Get(memoryMap *polkavm.MemoryMap, address uint32, length int) ([]byte, error) {
	var start uint32
	var memorySlice []byte
	if address >= memoryMap.ArgsDataAddress {
		start, memorySlice = memoryMap.ArgsDataAddress, m.argsData
	} else if address >= memoryMap.StackAddressLow {
		start, memorySlice = memoryMap.StackAddressLow, m.stack
	} else if address >= memoryMap.RWDataAddress {
		start, memorySlice = memoryMap.RWDataAddress, m.rwData
	} else if address >= memoryMap.RODataAddress {
		start, memorySlice = memoryMap.RODataAddress, m.roData
	} else {
		return nil, fmt.Errorf("memory access error")
	}

	offset := int(address - start)
	if offset+length > len(memorySlice) {
		return nil, fmt.Errorf("memory slice out of range, address %d, length: %d", address, length)
	}
	return memorySlice[offset : offset+length], nil
}

func (m *Memory) Set(memoryMap *polkavm.MemoryMap, address uint32, data []byte) error {
	var start uint32
	var memorySlice []byte
	var length = len(data)
	if address >= memoryMap.ArgsDataAddress {
		start, memorySlice = memoryMap.ArgsDataAddress, m.argsData
	} else if address >= memoryMap.StackAddressLow {
		start, memorySlice = memoryMap.StackAddressLow, m.stack
	} else if address >= memoryMap.RWDataAddress {
		start, memorySlice = memoryMap.RWDataAddress, m.rwData
	} else {
		return fmt.Errorf("memory access error")
	}

	offset := int(address - start)
	if offset+length > len(memorySlice) {
		return fmt.Errorf("memory slice out of range, address %d, length: %d %d %d", address, length, offset, len(memorySlice))
	}
	copy(memorySlice[offset:offset+length], data)
	return nil
}
