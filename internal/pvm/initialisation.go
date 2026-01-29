package pvm

import (
	"errors"
	"github.com/eigerco/strawberry/internal/safemath"
)

const (
	AddressSpaceSize               = 1 << 32
	DynamicAddressAlignment        = 2                           // Z_A = 2: The pvm dynamic address alignment factor (eq. A.18 v0.7.2)
	InputDataSize                  = 1 << 24                     // Z_I: The standard pvm program initialization input data size (eq. A.39 v0.7.2)
	MemoryZoneSize                 = 1 << 16                     // Z_Z: The standard pvm program initialization zone size (eq. A.39 v0.7.2)
	PageSize                       = 1 << 12                     // Z_P: The pvm memory page size (eq. 4.25)
	MaxPageIndex                   = AddressSpaceSize / PageSize // p = 2^32 / Z_P = 1 << 20
	AddressReturnToHost            = AddressSpaceSize - MemoryZoneSize
	StackAddressHigh               = AddressSpaceSize - 2*MemoryZoneSize - InputDataSize // 2^32 − 2Z_Z − Z_I
	ArgsAddressLow                 = AddressSpaceSize - MemoryZoneSize - InputDataSize   // 2^32 − Z_Z − Z_I
	RWAddressBase           uint64 = 2 * MemoryZoneSize
)

var (
	ErrMemoryLayoutOverflowsAddressSpace = errors.New("memory layout overflows address space")
)

// InitializeStandardProgram (eq. A.37 v0.7.2)
func InitializeStandardProgram(program *ProgramBlob, argsData []byte) (Memory, Registers, error) {
	ram, err := InitializeMemory(program.ROData, program.RWData, argsData, program.ProgramMemorySizes.StackSize, program.ProgramMemorySizes.InitialHeapPages)
	if err != nil {
		return Memory{}, Registers{}, err
	}
	regs := InitializeRegisters(len(argsData))
	return ram, regs, nil
}

// InitializeMemory (eq. A.42 v0.7.2)
func InitializeMemory(roData, rwData, argsData []byte, stackSize uint32, initialPages uint16) (Memory, error) {
	stackSizeRounded2Page, err := roundUpToPage(stackSize) // P(s)
	if err != nil {
		return Memory{}, err
	}
	stackSizeRounded2Zone, err := roundUpToZone(stackSize) // Z(s)
	if err != nil {
		return Memory{}, err
	}
	rwDataRounded2Zone, err := roundUpToZone(uint32(len(rwData)) + uint32(initialPages)*PageSize)
	if err != nil {
		return Memory{}, err
	}
	rwDataRounded2Page, err := roundUpToPage(uint32(len(rwData)))
	if err != nil {
		return Memory{}, err
	}
	roDataRounded2Page, err := roundUpToPage(uint32(len(roData)))
	if err != nil {
		return Memory{}, err
	}
	roDataRounded2Zone, err := roundUpToZone(uint32(len(roData)))
	if err != nil {
		return Memory{}, err
	}
	argsDataRounded2Page, err := roundUpToPage(uint32(len(argsData)))
	if err != nil {
		return Memory{}, err
	}
	// 5Z_Z + Z(|o|) + Z(|w| + zZ_P) + Z(s) + Z_I ≤ 2^32 (eq. A.41 v0.7.2)
	v, ok := safemath.Mul[uint32](5, MemoryZoneSize)
	if !ok {
		return Memory{}, ErrMemoryLayoutOverflowsAddressSpace
	}
	v, ok = safemath.Add(v, rwDataRounded2Zone)
	if !ok {
		return Memory{}, ErrMemoryLayoutOverflowsAddressSpace
	}
	v, ok = safemath.Add(v, stackSizeRounded2Zone)
	if !ok {
		return Memory{}, ErrMemoryLayoutOverflowsAddressSpace
	}
	_, ok = safemath.Add(v, InputDataSize)
	if !ok {
		return Memory{}, ErrMemoryLayoutOverflowsAddressSpace
	}

	mem := Memory{
		// if Z_Z		≤ i < Z_Z + |o|
		// if Z_Z + |o| ≤ i < Z_Z + P(|o|)
		ro: memorySegment{
			address: MemoryZoneSize,                        // Z_Z
			access:  ReadOnly,                              // a: R
			data:    copySized(roData, roDataRounded2Page), // v: o_(i−Z_Z)
		},
		// if 2Z_Z + Z(|o|) 	  ≤ i < 2Z_Z + Z(|o|) + |w|
		// if 2Z_Z + Z(|o|) + |w| ≤ i < 2Z_Z + Z(|o|) + P(|w|) + zZ_P
		rw: memorySegment{
			address: 2*MemoryZoneSize + roDataRounded2Zone,                               // 2Z_Z + Z(|o|)
			access:  ReadWrite,                                                           // a: W
			data:    copySized(rwData, rwDataRounded2Page+uint32(initialPages)*PageSize), // v: w_(i−(2Z_Z +Z(|o|)))
		},
		// if 2^32 − 2Z_Z − Z_I − P(s) ≤ i < 2^32 − 2Z_Z − Z_I
		stack: memorySegment{
			address: StackAddressHigh - stackSizeRounded2Page, // 2^32 − 2Z_Z − Z_I − P(s)
			access:  ReadWrite,
			data:    make([]byte, stackSizeRounded2Page),
		},
		// if 2^32 − Z_Z − Z_I 		 ≤ i < 2^32 − Z_Z − Z_I + |a|
		// if 2^32 − Z_Z − Z_I + |a| ≤ i < 2^32 − Z_Z − Z_I + P(|a|)
		args: memorySegment{
			address: ArgsAddressLow,
			access:  ReadOnly,
			data:    copySized(argsData, argsDataRounded2Page),
		},
	}
	mem.ro.end = mem.ro.address + uint32(len(mem.ro.data))
	mem.rw.end = mem.rw.address + uint32(len(mem.rw.data))
	mem.stack.end = mem.stack.address + uint32(len(mem.stack.data))
	mem.args.end = mem.args.address + uint32(len(mem.args.data))
	mem.currentHeapPointer = mem.rw.end
	return mem, nil
}

func InitializeCustomMemory(roAddr, rwAddr, stackAddr, argsAddr, roSize, rwSize, stackSize, argsSize uint32) Memory {
	mem := Memory{
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
	mem.ro.end = mem.ro.address + uint32(len(mem.ro.data))
	mem.rw.end = mem.rw.address + uint32(len(mem.rw.data))
	mem.stack.end = mem.stack.address + uint32(len(mem.stack.data))
	mem.args.end = mem.args.address + uint32(len(mem.args.data))
	mem.currentHeapPointer = mem.rw.end
	return mem
}

// InitializeRegisters (eq. A.43 v0.7.2)
func InitializeRegisters(argsLen int) Registers {
	return Registers{
		R0: AddressReturnToHost, // 2^32 − 2^16 		if i = 0
		R1: StackAddressHigh,    // 2^32 − 2Z_Z − Z_I 	if i = 1
		R7: ArgsAddressLow,      // 2^32 − Z_Z − Z_I 	if i = 7
		R8: uint64(argsLen),     // |a| 				if i = 8
		// 0 otherwise
	}
}

func copySized(data []byte, size uint32) []byte {
	dst := make([]byte, size)
	copy(dst, data)
	return dst
}

// roundUpToPage let P(x ∈ N) ≡ Z_P⌈x/Z_P⌉ (eq. A.40 v0.7.2)
func roundUpToPage(value uint32) (uint32, error) {
	v, ok := safemath.Add(value, PageSize-1)
	if !ok {
		return 0, ErrMemoryLayoutOverflowsAddressSpace
	}
	roundedUpVal, ok := safemath.Mul(PageSize, v/PageSize)
	if !ok {
		return 0, ErrMemoryLayoutOverflowsAddressSpace
	}
	return roundedUpVal, nil
}

// roundUpToZone let Z(x ∈ N) ≡ Z_Z⌈x/Z_Z⌉ (eq. A.40 v0.7.2)
func roundUpToZone(value uint32) (uint32, error) {
	v, ok := safemath.Add(value, MemoryZoneSize-1)
	if !ok {
		return 0, ErrMemoryLayoutOverflowsAddressSpace
	}
	roundedUpVal, ok := safemath.Mul(MemoryZoneSize, v/MemoryZoneSize)
	if !ok {
		return 0, ErrMemoryLayoutOverflowsAddressSpace
	}
	return roundedUpVal, nil
}
