package interpreter

import (
	"github.com/eigerco/strawberry/internal/polkavm"
	"github.com/eigerco/strawberry/pkg/serialization/codec/jam"
)

var _ polkavm.Mutator = &Instance{}

func Instantiate(program []byte, instructionOffset uint64, gasLimit polkavm.Gas, regs polkavm.Registers, memory polkavm.Memory) (*Instance, error) {
	code, bitmask, jumpTable, err := polkavm.Deblob(program)
	if err != nil {
		return nil, err
	}

	// ϖ ≡ [0] ⌢ [n + 1 + skip(n) | n <− N_|c| ∧ kn = 1 ∧ cn ∈ T ] (eq. A.5 v0.7.0)
	basicBlockInstructions := map[uint64]struct{}{0: {}}

	for i, b := range bitmask {
		if b && polkavm.Opcode(code[i]).IsBasicBlockTermination() {
			basicBlockInstructions[uint64(i)+1+polkavm.Skip(uint64(i), bitmask)] = struct{}{}
		}
	}

	return &Instance{
		memory:                 memory,
		regs:                   regs,
		instructionCounter:     instructionOffset,
		gasRemaining:           int64(gasLimit),
		code:                   code,
		jumpTable:              jumpTable,
		bitmask:                append(bitmask, true), // k ⌢ [1, 1, ... ]
		basicBlockInstructions: basicBlockInstructions,
	}, nil
}

type Instance struct {
	memory                 polkavm.Memory      // The memory sequence; a member of the set M (μ)
	regs                   polkavm.Registers   // The registers (φ)
	instructionCounter     uint64              // The instruction counter (ı)
	gasRemaining           int64               // The gas counter (ϱ). For single step and basic invocation use Z_G (int64) according to GP the gas result can be negative
	code                   []byte              // ζ
	jumpTable              []uint64            // j
	bitmask                jam.BitSequence     // k
	basicBlockInstructions map[uint64]struct{} // ϖ
}

// skip ı′ = ı + 1 + skip(ı) (eq. A.7 v0.7.0)
func (i *Instance) skip() {
	i.instructionCounter += 1 + polkavm.Skip(i.instructionCounter, i.bitmask)
}

func (i *Instance) deductGas(cost polkavm.Gas) error {
	if i.gasRemaining < int64(cost) {
		return polkavm.ErrOutOfGas
	}
	i.gasRemaining -= int64(cost)
	return nil
}

// load E−1_n(μ↺_{a...+n}) where a is address and n is length
func (i *Instance) load(address uint64, length int, v any) error {
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
func (i *Instance) store(address uint64, v any) error {
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

func (i *Instance) setAndSkip(dst polkavm.Reg, value uint64) {
	i.regs[dst] = value
	i.skip()
}

// branch (b, C) =⇒ (ε, ı′) (eq. A.17 v0.7.0)
func (i *Instance) branch(condition bool, target uint64) error {
	if condition {
		// (☇, ı) if b ∉ ϖ
		if _, ok := i.basicBlockInstructions[target]; !ok {
			return polkavm.ErrPanicf("indirect jump to non-block-termination instruction target=%d opcode=%d", target, i.code[target])
		}
		// (▸, b) otherwise
		i.instructionCounter = target
	} else {
		// (▸, ı) if ¬C
		i.skip()
	}
	return nil
}

// djump (a) =⇒ (ε, ı′) (eq. A.18 v0.7.0)
func (i *Instance) djump(address0 uint64) error {
	address := uint32(address0)
	// (∎, ı) if a = 2^32 − 2^16
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
