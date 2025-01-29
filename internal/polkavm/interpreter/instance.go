package interpreter

import (
	"github.com/eigerco/strawberry/internal/polkavm"
)

func Instantiate(instructionOffset uint32, gasLimit polkavm.Gas, regs polkavm.Registers, memory polkavm.Memory) *instance {
	return &instance{
		memory:              memory,
		regs:                regs,
		instructionOffset:   instructionOffset,
		offsetForBasicBlock: make(map[uint32]int),
		gasRemaining:        gasLimit,
	}
}

type instance struct {
	memory              polkavm.Memory    // The memory sequence; a member of the set M (μ)
	regs                polkavm.Registers // The registers (ω)
	instructionOffset   uint32            // The instruction counter (ı)
	instructionLength   uint32
	cycleCounter        uint64
	offsetForBasicBlock map[uint32]int
	instructions        []polkavm.Instruction // The instruction sequence (ζ)
	instructionIndex    int                   // we keep an internal instruction index for convenience
	gasRemaining        polkavm.Gas           // The gas counter (ϱ)
}

func (i *instance) startBasicBlock(program *polkavm.Program) {
	if compiledOffset, ok := i.offsetForBasicBlock[i.instructionOffset]; ok {
		i.instructionIndex = compiledOffset
	} else {
		i.instructionIndex = len(i.instructions)
		for index, instr := range program.CodeAndJumpTable.Instructions {
			if instr.Offset == i.instructionOffset {
				i.addInstructionsForBlock(program.CodeAndJumpTable.Instructions[index:])
				break
			}
		}
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
	if len(i.instructions) == i.instructionIndex {
		gasCost, ok := polkavm.GasCosts[polkavm.Trap]
		if !ok {
			return instruction, polkavm.ErrPanicf("trap opcode not defined in GasCosts map")
		}
		i.DeductGas(gasCost)

		return instruction, polkavm.ErrPanicf("unexpected program termination")
	}
	instruction = i.instructions[i.instructionIndex]
	i.instructionOffset = instruction.Offset
	i.instructionLength = instruction.Length

	gasCost, ok := polkavm.GasCosts[instruction.Opcode]
	if !ok {
		return instruction, polkavm.ErrPanicf("unknown opcode: %v", instruction.Opcode)
	}
	if i.gasRemaining < gasCost {
		return instruction, polkavm.ErrOutOfGas
	}

	i.DeductGas(gasCost)

	return instruction, nil
}

func (i *instance) NextOffsets() {
	i.instructionOffset += i.instructionLength
	i.instructionIndex += 1
}
func (i *instance) DeductGas(cost polkavm.Gas) {
	i.gasRemaining -= cost
}
