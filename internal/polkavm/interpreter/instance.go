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

// InitRegs Equation 246: standard program initialization, registers
func InitRegs(i polkavm.Instance, args []byte) {
	i.SetReg(polkavm.RA, 1<<32-1<<16)
	i.SetReg(polkavm.SP, 1<<32-2*(1<<16)-2<<24)
	i.SetReg(polkavm.A0, 1<<32-1<<16-2<<24)
	i.SetReg(polkavm.A1, uint32(len(args)))
}

func Instantiate(memory *Memory, instructionOffset uint32, gasLimit int64) polkavm.Instance {
	return &instance{
		memory:              memory,
		regs:                map[polkavm.Reg]uint32{},
		instructionOffset:   instructionOffset,
		offsetForBasicBlock: make(map[uint32]int),
		gasRemaining:        gasLimit,
	}
}

type instance struct {
	memory              *Memory                // The memory sequence; a member of the set M (μ)
	regs                map[polkavm.Reg]uint32 // The registers (ω)
	instructionOffset   uint32
	instructionLength   uint32
	cycleCounter        uint64
	offsetForBasicBlock map[uint32]int
	instructions        []polkavm.Instruction // The instruction sequence (ζ)
	instructionCounter  int                   // The instruction counter (ı)
	gasRemaining        int64                 // The gas counter (ϱ)
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
	return i.memory.Get(memoryMap, address, length)
}

func (i *instance) SetMemory(memoryMap *polkavm.MemoryMap, address uint32, data []byte) error {
	return i.memory.Set(memoryMap, address, data)
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
		gasCost, ok := polkavm.GasCosts[polkavm.Trap]
		if !ok {
			return instruction, fmt.Errorf("trap opcode not defined in GasCosts map")
		}
		i.DeductGas(gasCost)

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
		return instruction, polkavm.ErrOutOfGas
	}

	i.DeductGas(gasCost)

	return instruction, nil
}

func (i *instance) NextOffsets() {
	i.instructionOffset += i.instructionLength
	i.instructionCounter += 1
}
func (i *instance) DeductGas(cost int64) {
	i.gasRemaining -= cost
}
