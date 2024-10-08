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

type callFunc func(instance polkavm.Instance) error

type instance struct {
	memory              *memory
	regs                map[polkavm.Reg]uint32
	instructionOffset   uint32
	instructionLength   uint32
	cycleCounter        uint64
	offsetForBasicBlock map[uint32]int
	instructions        []polkavm.Instruction
	instructionCounter  int
	gasRemaining        int64
}

func (i *instance) GetReg(reg polkavm.Reg) uint32 {
	return i.regs[reg]
}

func (i *instance) SetReg(reg polkavm.Reg, val uint32) {
	i.regs[reg] = val
}

func (i *instance) GetInstructionOffset() uint32 {
	return i.instructionOffset
}

func (i *instance) SetInstructionOffset(target uint32) {
	i.instructionOffset = target
}

func (i *instance) GasRemaining() int64 {
	return i.gasRemaining
}

func (i *instance) GetMemory(memoryMap *polkavm.MemoryMap, address uint32, length int) ([]byte, error) {
	var start uint32
	var memorySlice []byte
	if address >= memoryMap.StackAddressLow {
		start, memorySlice = memoryMap.StackAddressLow, i.memory.stack
	} else if address >= memoryMap.RWDataAddress {
		start, memorySlice = memoryMap.RWDataAddress, i.memory.rwData
	} else if address >= memoryMap.RODataAddress {
		start, memorySlice = memoryMap.RODataAddress, memoryMap.ROData
	} else {
		return nil, fmt.Errorf("memory access error")
	}

	offset := int(address - start)
	if offset+length > len(memorySlice) {
		return nil, fmt.Errorf("memory slice out of range, address %d, length: %d", address, length)
	}
	return memorySlice[offset : offset+length], nil
}

func (i *instance) SetMemory(memoryMap *polkavm.MemoryMap, address uint32, data []byte) error {
	var start uint32
	var memorySlice []byte
	var length = len(data)
	if address >= memoryMap.StackAddressLow {
		start, memorySlice = memoryMap.StackAddressLow, i.memory.stack
	} else if address >= memoryMap.RWDataAddress {
		start, memorySlice = memoryMap.RWDataAddress, i.memory.rwData
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

func (i *instance) Sbrk(memoryMap *polkavm.MemoryMap, size uint32) (uint32, error) {
	newHeapSize := i.memory.heapSize + size
	if newHeapSize > memoryMap.MaxHeapSize {
		return 0, fmt.Errorf("max heap size exceeded")
	}

	i.memory.heapSize = newHeapSize
	heapTop := memoryMap.HeapBase + newHeapSize
	if heapTop > memoryMap.RWDataAddress+uint32(len(i.memory.rwData)) {
		nextPage, err := polkavm.AlignToNextPageInt(int(memoryMap.PageSize), int(heapTop))
		if err != nil {
			return 0, err
		}
		newSize := nextPage - int(memoryMap.RWDataAddress)
		rwData := i.memory.rwData
		i.memory.rwData = make([]byte, newSize)
		copy(i.memory.rwData, rwData)
	}

	return heapTop, nil
}

func (i *instance) StartBasicBlock(program *polkavm.Program) {
	if compiledOffset, ok := i.offsetForBasicBlock[i.instructionOffset]; ok {
		i.instructionCounter = compiledOffset
	} else {
		i.instructionCounter = len(i.instructions)
		instructions, ok := program.GetInstructionsForOffset(i.instructionOffset)
		if !ok {
			return
		}
		i.addInstructionsForBlock(instructions)
	}
}

func (i *instance) addInstructionsForBlock(instructions []polkavm.Instruction) {
	startingOffset := len(i.instructions)
	for _, instruction := range instructions {
		i.instructions = append(i.instructions, instruction)
		if instruction.IsBasicBlockTermination() {
			break
		}
	}
	if len(i.instructions) == startingOffset {
		return
	}
	i.offsetForBasicBlock[i.instructionOffset] = startingOffset
}

func (i *instance) NextInstruction() (instruction polkavm.Instruction, err error) {
	i.cycleCounter += 1
	if len(i.instructions) == i.instructionCounter {
		return instruction, &TrapError{fmt.Errorf("unexpected program termination")}
	}
	instruction = i.instructions[i.instructionCounter]
	i.instructionOffset = instruction.Offset
	i.instructionLength = instruction.Length

	gasCost, ok := polkavm.GasCosts[instruction.Opcode]
	if !ok {
		return instruction, fmt.Errorf("unknown opcode: %v", instruction.Opcode)
	}
	if i.gasRemaining < gasCost {
		return instruction, errOutOfGas
	}

	i.deductGas(gasCost)
	return instruction, nil
}

func (i *instance) NextOffsets() {
	i.instructionOffset += i.instructionLength
	i.instructionCounter += 1
}
func (i *instance) deductGas(cost int64) {
	if cost > i.gasRemaining {
		i.gasRemaining = 0
	} else {
		i.gasRemaining -= cost
	}
}

func newBasicMemory(memoryMap *polkavm.MemoryMap, rwData []byte) *memory {
	m := &memory{
		rwData: make([]byte, memoryMap.RWDataSize),
		stack:  make([]byte, memoryMap.StackSize),
	}
	copy(m.rwData, rwData)
	return m
}

type memory struct {
	rwData   []byte
	stack    []byte
	heapSize uint32
}
