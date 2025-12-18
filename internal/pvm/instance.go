package pvm

import (
	"github.com/eigerco/strawberry/pkg/serialization/codec/jam"
)

func Instantiate(program []byte, instructionOffset uint64, gasLimit UGas, regs Registers, memory Memory) (*Instance, error) {
	code, bitmask, jumpTable, err := Deblob(program)
	if err != nil {
		return nil, err
	}

	// ϖ ≡ [0] ⌢ [n + 1 + skip(n) | n <− N_|c| ∧ kn = 1 ∧ cn ∈ T ] (eq. A.5 v0.7.2)
	basicBlockInstructions := map[uint64]struct{}{0: {}}

	for i, b := range bitmask {
		if b && Opcode(code[i]).IsBasicBlockTermination() {
			basicBlockInstructions[uint64(i)+1+Skip(uint64(i), bitmask)] = struct{}{}
		}
	}

	return &Instance{
		memory:                 memory,
		regs:                   regs,
		instructionCounter:     instructionOffset,
		gasRemaining:           Gas(gasLimit),
		code:                   code,
		jumpTable:              jumpTable,
		bitmask:                append(bitmask, true), // k ⌢ [1, 1, ... ]
		basicBlockInstructions: basicBlockInstructions,
		instructionsCache:      make([]*instructionCache, len(code)),
	}, nil
}

type Instance struct {
	memory                 Memory              // The memory sequence; a member of the set M (μ)
	regs                   Registers           // The registers (φ)
	instructionCounter     uint64              // The instruction counter (ı)
	gasRemaining           Gas                 // The gas counter (ϱ). For single step and basic invocation use Z_G (int64) according to GP the gas result can be negative
	code                   []byte              // ζ
	jumpTable              []uint64            // j
	bitmask                jam.BitSequence     // k
	basicBlockInstructions map[uint64]struct{} // ϖ

	skipLen           uint64
	instructionsCache []*instructionCache
	loadBuf           [8]byte // reusable buffer for load operations
}

type instructionCache struct {
	reg [3]Reg
	val [2]uint64
}

// skip ı′ = ı + 1 + skip(ı) (eq. A.9 v0.7.2)
func (i *Instance) skip() {
	i.instructionCounter += 1 + i.skipLen
}

func (i *Instance) deductGas(cost Gas) error {
	if i.gasRemaining < cost {
		return ErrOutOfGas
	}
	i.gasRemaining -= cost
	return nil
}

// load E−1_n(μ↺_{a...+n}) where a is address and n is length
func (i *Instance) load(address uint64, length int, v any) error {
	slice := i.loadBuf[:length]
	if err := i.memory.Read(uint32(address), slice); err != nil {
		return err
	}

	switch p := v.(type) {
	case *uint8:
		*p = jam.DecodeUint8(slice)
	case *int8:
		*p = int8(jam.DecodeUint8(slice))
	case *uint16:
		*p = jam.DecodeUint16(slice)
	case *int16:
		*p = int16(jam.DecodeUint16(slice))
	case *uint32:
		*p = jam.DecodeUint32(slice)
	case *int32:
		*p = int32(jam.DecodeUint32(slice))
	case *uint64:
		*p = jam.DecodeUint64(slice)
	case *int64:
		*p = int64(jam.DecodeUint64(slice))
	default:
		return jam.Unmarshal(slice, v)
	}
	return nil
}

// store μ′↺_{a...+|v|} = E_|v|(v) where a is address and |v| is the length in bytes required to store v
func (i *Instance) store(address uint64, v any) error {
	var data []byte
	switch val := v.(type) {
	case uint8:
		data = jam.EncodeUint8(val)
	case int8:
		data = jam.EncodeUint8(uint8(val))
	case uint16:
		data = jam.EncodeUint16(val)
	case int16:
		data = jam.EncodeUint16(uint16(val))
	case uint32:
		data = jam.EncodeUint32(val)
	case int32:
		data = jam.EncodeUint32(uint32(val))
	case uint64:
		data = jam.EncodeUint64(val)
	case int64:
		data = jam.EncodeUint64(uint64(val))
	default:
		var err error
		data, err = jam.Marshal(v)
		if err != nil {
			return err
		}
	}
	if err := i.memory.Write(uint32(address), data); err != nil {
		return err
	}

	i.skip()
	return nil
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
