package main

import (
	"fmt"
	"math"
)

func main() {
	//state.ServiceAccount{}
	//state.State{}
	println("test1", 1<<32)
	println("test2", uint(math.Pow(2, 32)))
	println("len", [32]byte{} == [32]byte{1})
	println("VmAddrUserStackHigh", VmAddrUserStackHigh)
	var a float64 = 32
	var x float64 = 2
	fmt.Printf("a %f", a*math.Ceil(x/a))

	println(math.MaxUint32, 1<<32)
}

const (
	Zp   = 1 << 12
	Zq   = 1 << 16
	Zi   = 1 << 24
	max  = 1 << 32
	REG0 = max - 1<<16 // check
	REG1 = max - 2*Zq - Zi
	REG7 = max - Zq - Zi
)

const (
	AddressSpaceSize uint64 = 0x100000000
	VmMinPageSize           = 0x1000  // The minimum page size of the VM
	VmMaxPageSize           = 0x10000 // The maximum page size of the VM.

	VmAddrReturnToHost         = 0xffff0000                                       // The address which, when jumped to, will return to the host.
	VmAddrUserStackHigh uint32 = uint32(AddressSpaceSize - uint64(VmMaxPageSize)) // The address at which the program's stack starts inside of the VM.
)

//func RAM(R int, o []byte) {
//	for i := 0; i < R; i++ {
//		if Zq <= i && i < Zq+len(o) {
//			binary.LittleEndian.Uint64()
//		}
//	}
//}

func P(x uint32) uint32 {
	return Zp * uint32(math.Ceil(float64(x)/Zp))
}

func Q(x uint32) uint32 {
	return Zq * uint32(math.Ceil(float64(x)/Zq))
}
