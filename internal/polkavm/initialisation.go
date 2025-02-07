package polkavm

import (
	"errors"
)

const (
	AddressSpaceSize               = 1 << 32
	DynamicAddressAlignment        = 2                           // Z_A = 2: The pvm dynamic address alignment factor. See equation A.15.
	InputDataSize                  = 1 << 24                     // Z_I: The standard pvm program initialization input data size (equation A.7)
	MemoryZoneSize                 = 1 << 16                     // Z_Z: The standard pvm program initialization zone size (section A.7)
	PageSize                       = 1 << 12                     // Z_P: The pvm memory page size (equation 4.25)
	MaxPageIndex                   = AddressSpaceSize / PageSize // p = 2^32 / Z_P = 1 << 20
	AddressReturnToHost            = AddressSpaceSize - MemoryZoneSize
	StackAddressHigh               = AddressSpaceSize - 2*MemoryZoneSize - InputDataSize // 2^32 − 2Z_Z − Z_I
	ArgsAddressLow                 = AddressSpaceSize - MemoryZoneSize - InputDataSize   // 2^32 − Z_Z − Z_I
	RWAddressBase           uint32 = 2 * MemoryZoneSize
)

var (
	ErrMemoryLayoutOverflowsAddressSpace = errors.New("memory layout overflows address space")
)

// InitializeStandardProgram (A.7)
func InitializeStandardProgram(program *Program, argsData []byte) (Memory, Registers, error) {
	ram, err := InitializeMemory(program.ROData, program.RWData, argsData, program.ProgramMemorySizes.StackSize, program.ProgramMemorySizes.InitialHeapPages)
	if err != nil {
		return Memory{}, Registers{}, err
	}
	regs := InitializeRegisters(len(argsData))
	return ram, regs, nil
}

// InitializeMemory (eq. A.36)
func InitializeMemory(roData, rwData, argsData []byte, stackSize uint32, initialPages uint16) (Memory, error) {
	// 5Z_Z + Z(|o|) + Z(|w| + zZ_P) + Z(s) + Z_I ≤ 2^32 (eq. A.35)
	if 5*MemoryZoneSize+
		int(alignToZone(uint32(len(rwData))+uint32(initialPages)*PageSize))+
		int(alignToZone(stackSize))+
		InputDataSize > AddressSpaceSize {
		return Memory{}, ErrMemoryLayoutOverflowsAddressSpace
	}
	stackSizeAligned := alignToPage(stackSize) // P(s)
	return Memory{
		// if Z_Z		≤ i < Z_Z + |o|
		// if Z_Z + |o| ≤ i < Z_Z + P(|o|)
		ro: memorySegment{
			address: MemoryZoneSize,                                      // Z_Z
			access:  ReadOnly,                                            // A: R
			data:    copySized(roData, alignToPage(uint32(len(roData)))), // V: o_(i−Z_Z)
		},
		// if 2Z_Z + Z(|o|) 	  ≤ i < 2Z_Z + Z(|o|) + |w|
		// if 2Z_Z + Z(|o|) + |w| ≤ i < 2Z_Z + Z(|o|) + P(|w|) + zZ_P
		rw: memorySegment{
			address: 2*MemoryZoneSize + alignToZone(uint32(len(roData))),                               // 2Z_Z + Z(|o|)
			access:  ReadWrite,                                                                         // A: W
			data:    copySized(rwData, alignToPage(uint32(len(rwData)))+uint32(initialPages)*PageSize), // V: w_(i−(2Z_Z +Z(|o|)))
		},
		// if 2^32 − 2Z_Z − Z_I − P(s) ≤ i < 2^32 − 2Z_Z − Z_I
		stack: memorySegment{
			address: StackAddressHigh - stackSizeAligned, // 2^32 − 2Z_Z − Z_I − P(s)
			access:  ReadWrite,
			data:    make([]byte, stackSizeAligned),
		},
		// if 2^32 − Z_Z − Z_I 		 ≤ i < 2^32 − Z_Z − Z_I + |a|
		// if 2^32 − Z_Z − Z_I + |a| ≤ i < 2^32 − Z_Z − Z_I + P(|a|)
		args: memorySegment{
			address: ArgsAddressLow,
			access:  ReadOnly,
			data:    copySized(argsData, alignToPage(uint32(len(argsData)))),
		},
	}, nil
}

func InitializeCustomMemory(roAddr, rwAddr, stackAddr, argsAddr, roSize, rwSize, stackSize, argsSize uint32) Memory {
	return Memory{
		ro: memorySegment{
			address: roAddr,
			access:  ReadOnly,
			data:    make([]byte, roSize),
		},
		rw: memorySegment{
			address: rwAddr,
			access:  ReadWrite,
			data:    make([]byte, rwSize),
		},
		stack: memorySegment{
			address: stackAddr,
			access:  ReadWrite,
			data:    make([]byte, stackSize),
		},
		args: memorySegment{
			address: argsAddr,
			access:  ReadOnly,
			data:    make([]byte, argsSize),
		},
	}
}

// InitializeRegisters (eq. A.37)
func InitializeRegisters(argsLen int) Registers {
	return Registers{
		RA: AddressReturnToHost, // 2^32 − 2^16 		if i = 0
		SP: StackAddressHigh,    // 2^32 − 2Z_Z − Z_I 	if i = 1
		A0: ArgsAddressLow,      // 2^32 − Z_Z − Z_I 	if i = 7
		A1: uint64(argsLen),     // |a| 				if i = 8
		// 0 otherwise
	}
}

func copySized(data []byte, size uint32) []byte {
	dst := make([]byte, size)
	copy(dst, data)
	return dst
}

// alignToPage let P(x ∈ N) ≡ ZP⌈x/Z_P⌉ (eq. A.34)
func alignToPage(value uint32) uint32 {
	if value&(PageSize-1) == 0 {
		return value
	}

	return (value + PageSize) & ^(uint32(PageSize) - 1)
}

// alignToPage let P(x ∈ N) ≡ ZP⌈x/Z_P⌉ (eq. A.34)
func alignToZone(value uint32) uint32 {
	if value&(MemoryZoneSize-1) == 0 {
		return value
	}

	return (value + MemoryZoneSize) & ^(uint32(MemoryZoneSize) - 1)
}
