package interpreter

import (
	"github.com/eigerco/strawberry/internal/polkavm"
	"github.com/eigerco/strawberry/pkg/serialization/codec/jam"
)

var _ polkavm.Mutator = &Instance{}

func Instantiate(program []byte, instructionOffset uint32, gasLimit polkavm.Gas, regs polkavm.Registers, memory polkavm.Memory) (*Instance, error) {
	code, bitmask, jumpTable, err := polkavm.Deblob(program)
	if err != nil {
		return nil, err
	}

	// ϖ ≡ [0] ⌢ [n + 1 + skip(n) | n <− N_|c| ∧ kn = 1 ∧ cn ∈ T ]
	basicBlockInstructions := map[uint32]struct{}{0: {}}

	for i, b := range bitmask {
		if b && polkavm.Opcode(code[i]).IsBasicBlockTermination() {
			basicBlockInstructions[uint32(i)+1] = struct{}{}
		}
	}

	return &Instance{
		memory:                 memory,
		regs:                   regs,
		instructionCounter:     instructionOffset,
		gasRemaining:           gasLimit,
		code:                   append(code, 0), // ζ ≡ c ⌢ [0, 0, ... ]
		jumpTable:              jumpTable,
		bitmask:                append(bitmask, true), // k ⌢ [1, 1, ... ]
		basicBlockInstructions: basicBlockInstructions,
	}, nil
}

type Instance struct {
	memory                 polkavm.Memory      // The memory sequence; a member of the set M (μ)
	regs                   polkavm.Registers   // The registers (ω)
	instructionCounter     uint32              // The instruction counter (ı)
	gasRemaining           polkavm.Gas         // The gas counter (ϱ)
	code                   []byte              // ζ
	jumpTable              []uint32            // j
	bitmask                jam.BitSequence     // k
	basicBlockInstructions map[uint32]struct{} // ϖ
}

func (i *Instance) skip() {
	i.instructionCounter += 1 + polkavm.Skip(i.instructionCounter, i.bitmask)
}

func (i *Instance) deductGas(cost polkavm.Gas) error {
	if i.gasRemaining < cost {
		return polkavm.ErrOutOfGas
	}
	i.gasRemaining -= cost
	return nil
}

// load E−1_n(μ↺_{a...+n}) where a is address and n is length
func (i *Instance) load(address uint32, length int, v any) error {
	slice := make([]byte, length)
	if err := i.memory.Read(address, slice); err != nil {
		return err
	}

	if err := jam.Unmarshal(slice, v); err != nil {
		return err
	}
	return nil
}

// store μ′↺_{a...+|v|} = E_|v|(v) where a is address and |v| is the length in bytes required to store v
func (i *Instance) store(address uint32, v any) error {
	data, err := jam.Marshal(v)
	if err != nil {
		return err
	}
	if err = i.memory.Write(address, data); err != nil {
		return err
	}

	i.skip()
	return nil
}

func (i *Instance) setAndSkip32(dst polkavm.Reg, value uint32) {
	i.regs[dst] = uint64(value)
	i.skip()
}

func (i *Instance) setAndSkip64(dst polkavm.Reg, value uint64) {
	i.regs[dst] = value
	i.skip()
}

// branch (b, C) =⇒ (ε, ı′) (eq. A.16)
func (i *Instance) branch(condition bool, target uint32) error {
	if condition {
		// (☇, ı) if b ∉ ϖ
		if _, ok := i.basicBlockInstructions[target]; !ok {
			return polkavm.ErrPanicf("indirect jump to non-block-termination instruction")
		}
		// (▸, b) otherwise
		i.instructionCounter = target
	} else {
		// (▸, ı) if ¬C
		i.skip()
	}
	return nil
}

// djump (a) =⇒ (ε, ı′) (eq. A.17)
func (i *Instance) djump(address uint32) error {
	// (∎, ı) if a = 232 − 216
	if address == polkavm.AddressReturnToHost {
		return polkavm.ErrHalt
	}

	// (☇, ı) if a = 0 ∨ a > |j| ⋅ ZA ∨ a mod ZA ≠ 0
	if address == 0 || int(address) > len(i.jumpTable)*polkavm.DynamicAddressAlignment || address%polkavm.DynamicAddressAlignment != 0 {
		return polkavm.ErrPanicf("indirect jump to address %v invalid", address)
	}

	// (☇, ı) if j_(a/ZA)−1 j+(a/ZA)−1 ∉ ϖ
	instructionOffset := i.jumpTable[(address/polkavm.DynamicAddressAlignment)-1]
	if _, ok := i.basicBlockInstructions[instructionOffset]; !ok {
		return polkavm.ErrPanicf("indirect jump to address %v is non block-termination instruction", address)
	}

	// (▸, j_(a/ZA)−1) otherwise
	i.instructionCounter = instructionOffset
	return nil
}
