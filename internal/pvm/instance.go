package pvm

func Instantiate(program []byte, instructionOffset uint64, gasLimit UGas, regs Registers, memory Memory) (*Instance, error) {
	code, bitmask, jumpTable, err := Deblob(program)
	if err != nil {
		return nil, err
	}

	// Precompute skip lengths for all positions
	p := initProgram(code, bitmask, jumpTable)

	// ϖ ≡ [0] ⌢ [n + 1 + skip(n) | n <− N_|c| ∧ kn = 1 ∧ cn ∈ T ] (eq. A.5 v0.7.2)
	basicBlockInstructions := map[uint64]struct{}{0: {}}

	for i, b := range bitmask {
		if b && Opcode(code[i]).IsBasicBlockTermination() {
			basicBlockInstructions[uint64(i)+1+uint64(p.skip(uint64(i)))] = struct{}{}
		}
	}
	gasCostsMap := buildGasCostsMap(p, basicBlockInstructions)
	return &Instance{
		memory:                 memory,
		regs:                   regs,
		instructionCounter:     instructionOffset,
		gasRemaining:           Gas(gasLimit),
		program:                p,
		basicBlockInstructions: basicBlockInstructions,
		gasCostsMap:            gasCostsMap,
	}, nil
}

type Instance struct {
	*program

	memory                 Memory              // The memory sequence; a member of the set M (μ)
	regs                   Registers           // The registers (φ)
	instructionCounter     uint64              // The instruction counter (ı)
	gasRemaining           Gas                 // The gas counter (ϱ). For single step and basic invocation use Z_G (int64) according to GP the gas result can be negative
	gasChange              bool                // ˜ϱ
	basicBlockInstructions map[uint64]struct{} // ϖ
	gasCostsMap            map[uint64]Gas      // ϱ∆
	skipLen                uint8
	loadBuf                [8]byte // reusable buffer for load operations
	storeBuf               [8]byte // reusable buffer for store operations
}

// skip ı′ = ı + 1 + skip(ı) (eq. A.9 v0.7.2)
func (i *Instance) skip() {
	i.instructionCounter += 1 + uint64(i.skipLen)
}

func (i *Instance) setAndSkip(dst Reg, value uint64) {
	i.regs[dst] = value
	i.skip()
}

// branch (b, C) =⇒ (ε, ı′) (eq. A.17 v0.7.2)
func (i *Instance) branch(condition bool, target uint64) error {
	if condition {
		// (☇, ı) if b ∉ ϖ
		if _, ok := i.basicBlockInstructions[target]; !ok {
			return ErrPanicf("indirect jump to non-block-termination instruction target=%d opcode=%d", target, i.code[target])
		}
		// (▸, b) otherwise
		i.instructionCounter = target
	} else {
		// (▸, ı) if ¬C
		i.skip()
	}
	return nil
}

// djump (a) =⇒ (ε, ı′) (eq. A.18 v0.7.2)
func (i *Instance) djump(address uint32) error {
	// (∎, ı) if a = 2^32 − 2^16
	if address == AddressReturnToHost {
		return ErrHalt
	}

	// (☇, ı) if a = 0 ∨ a > |j| ⋅ ZA ∨ a mod ZA ≠ 0
	if address == 0 || int(address) > len(i.jumpTable)*DynamicAddressAlignment || address%DynamicAddressAlignment != 0 {
		return ErrPanicf("indirect jump to address %v invalid", address)
	}

	// (☇, ı) if j_(a/ZA)−1 j+(a/ZA)−1 ∉ ϖ
	instructionOffset := i.jumpTable[(address/DynamicAddressAlignment)-1]
	if _, ok := i.basicBlockInstructions[instructionOffset]; !ok {
		return ErrPanicf("indirect jump to address %v is non block-termination instruction", address)
	}

	// (▸, j_(a/ZA)−1) otherwise
	i.instructionCounter = instructionOffset
	return nil
}

// OverwriteMemoryMapRO overwrites memory map for read-only memory
func (i *Instance) OverwriteMemoryMapRO(address, length uint32) {
	i.memory.ro = memorySegment{
		address: address,
		end:     address + length,
		data:    make([]byte, length),
		access:  ReadOnly,
	}
}

// OverwriteMemoryMapRW overwrites memory map for read-write memory
func (i *Instance) OverwriteMemoryMapRW(address, length uint32) {
	i.memory.rw = memorySegment{
		address: address,
		end:     address + length,
		data:    make([]byte, length),
		access:  ReadWrite,
	}
}

// OverwriteMemoryMapStack overwrites memory map for stack memory
func (i *Instance) OverwriteMemoryMapStack(address, length uint32) {
	i.memory.stack = memorySegment{
		address: address,
		end:     address + length,
		data:    make([]byte, length),
		access:  ReadWrite,
	}
}

// OverwriteMemory overwrites memory regardless if the memory page is writable or not
func (i *Instance) OverwriteMemory(address uint32, contents []byte) error {
	pageIndex := address / PageSize
	access := i.memory.GetAccess(pageIndex)
	err := i.memory.SetAccess(pageIndex, ReadWrite)
	if err != nil {
		return err
	}
	if err = i.memory.Write(address, contents); err != nil {
		return err
	}
	return i.memory.SetAccess(pageIndex, access)
}

// OverwriteRegister overwrites one register
func (i *Instance) OverwriteRegister(index, value uint64) {
	i.regs[index] = value
}

// OverwriteGasCostsMap overwrites gas cost map
func (i *Instance) OverwriteGasCostsMap(gasCostsMap map[uint64]Gas) {
	i.gasCostsMap = gasCostsMap
}

// OverwriteSkip advances the instruction counter by the necessary skip amount
func (i *Instance) OverwriteSkip() {
	i.skip()
}

// basicBlockStart represents the start of a basic block for any ı within that basic block
// L(ı) = max(j∈ ϖ ∣ j≤ ı) (eq. A.7)
func (i *Instance) basicBlockStart(instrCounter uint64) uint64 {
	var best uint64

	for j := range i.basicBlockInstructions {
		if j <= instrCounter && j > best {
			best = j
		}
	}
	return best
}
