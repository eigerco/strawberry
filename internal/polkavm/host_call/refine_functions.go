package host_call

import (
	"errors"
	"math"

	"github.com/eigerco/strawberry/internal/block"
	"github.com/eigerco/strawberry/internal/common"
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/jamtime"
	. "github.com/eigerco/strawberry/internal/polkavm"
	"github.com/eigerco/strawberry/internal/polkavm/interpreter"
	"github.com/eigerco/strawberry/internal/service"
	"github.com/eigerco/strawberry/internal/work"
	"github.com/eigerco/strawberry/pkg/serialization/codec/jam"
)

type PreimageFetcher interface {
	FetchPreimage(hash crypto.Hash) ([]byte, error)
}

// HistoricalLookup ΩH(ϱ, φ, µ, (m, e), s, d, t)
func HistoricalLookup(
	gas Gas,
	regs Registers,
	mem Memory,
	ctxPair RefineContextPair,
	serviceId block.ServiceId,
	serviceState service.ServiceState,
	t jamtime.Timeslot,
) (Gas, Registers, Memory, RefineContextPair, error) {
	if gas < HistoricalLookupCost {
		return 0, regs, mem, ctxPair, ErrOutOfGas
	}
	gas -= HistoricalLookupCost

	omega7 := regs[A0]

	lookupID := block.ServiceId(omega7)
	if omega7 == math.MaxUint64 {
		lookupID = serviceId
	}

	a, exists := serviceState[lookupID]
	if !exists {
		return gas, regs, mem, RefineContextPair{}, ErrAccountNotFound
	}

	// let [h, o] = φ8..+2
	addressToRead, addressToWrite := regs[A1], regs[A2]

	hashData := make([]byte, 32)
	if err := mem.Read(addressToRead, hashData); err != nil {
		return gas, regs, mem, ctxPair, ErrPanicf(err.Error())
	}

	// Compute v = Λ(a, t, h) using the provided LookupPreimage function
	v := a.LookupPreimage(serviceId, t, crypto.Hash(hashData))

	if len(v) == 0 {
		return gas, withCode(regs, NONE), mem, ctxPair, nil
	}

	if err := writeFromOffset(&mem, addressToWrite, v, regs[A3], regs[A4]); err != nil {
		return gas, regs, mem, ctxPair, err
	}

	// set φ7 to |v|
	regs[A0] = uint64(len(v))

	return gas, regs, mem, ctxPair, nil
}

// Export ΩE(ϱ, φ, µ, (m, e), ς)
func Export(
	gas Gas,
	regs Registers,
	mem Memory,
	ctxPair RefineContextPair,
	exportOffset uint64,
) (Gas, Registers, Memory, RefineContextPair, error) {
	if gas < ExportCost {
		return 0, regs, mem, ctxPair, ErrOutOfGas
	}
	gas -= ExportCost

	p := regs[A0]               // φ7
	requestedLength := regs[A1] // φ8

	// let z = min(φ8,WG)
	z := min(requestedLength, common.SizeOfSegment)

	data := make([]byte, z)
	if err := mem.Read(p, data); err != nil {
		// x = ∇
		return gas, regs, mem, ctxPair, ErrPanicf(err.Error())
	}

	// Apply zero-padding Pn to data to make it WG-sized
	paddedData := work.ZeroPadding(data, common.SizeOfSegment)

	var segmentData work.Segment
	copy(segmentData[:], paddedData)

	currentCount := uint64(len(ctxPair.Segments))
	if exportOffset+currentCount >= work.MaxNumberOfImports {
		return gas, withCode(regs, FULL), mem, ctxPair, nil
	}

	// Append x to e
	ctxPair.Segments = append(ctxPair.Segments, segmentData)

	// φ7 = ς + |e|
	regs[A0] = exportOffset + uint64(len(ctxPair.Segments))

	return gas, regs, mem, ctxPair, nil
}

// Machine ΩM(ϱ, φ, µ, (m, e))
func Machine(
	gas Gas,
	regs Registers,
	mem Memory,
	ctxPair RefineContextPair,
) (Gas, Registers, Memory, RefineContextPair, error) {
	if gas < MachineCost {
		return 0, regs, mem, ctxPair, ErrOutOfGas
	}
	gas -= MachineCost

	// let [po, pz, i] = φ7...10
	po := regs[A0]
	pz := regs[A1]
	i := regs[A2]

	// p = µ[po ... po+pz]
	p := make([]byte, pz)
	err := mem.Read(po, p)
	if err != nil {
		// p = ∇
		return gas, regs, mem, ctxPair, ErrPanicf(err.Error())
	}

	if _, _, _, err = Deblob(p); err != nil {
		// if deblob(p) = ∇
		return gas, withCode(regs, HUH), mem, ctxPair, nil
	}

	// let n = min(n ∈ N, n ∉ K(m))
	n := findSmallestMissingKey(ctxPair.IntegratedPVMMap)

	pvm := IntegratedPVM{
		Code:               p,
		Ram:                Memory{}, // u = {V▸[0,0,...], A▸[∅, ∅, ...]}
		InstructionCounter: i,
	}

	// (φ′7,m′) = (n, m ∪ {n ↦ {p,u,i}})
	regs[A0] = n
	ctxPair.IntegratedPVMMap[n] = pvm

	return gas, regs, mem, ctxPair, nil
}

// Peek ΩP(ϱ, φ, µ, (m, e))
func Peek(
	gas Gas,
	regs Registers,
	mem Memory,
	ctxPair RefineContextPair,
) (Gas, Registers, Memory, RefineContextPair, error) {
	if gas < PeekCost {
		return 0, regs, mem, ctxPair, ErrOutOfGas
	}
	gas -= PeekCost

	n, o, sReg, z := regs[A0], regs[A1], regs[A2], regs[A3]

	u, exists := ctxPair.IntegratedPVMMap[n]
	if !exists {
		//n ∉ K(m)
		return gas, withCode(regs, WHO), mem, ctxPair, nil
	}

	// (m[n]u)[s...s+z]
	s := make([]byte, z)
	err := u.Ram.Read(sReg, s)
	if err != nil {
		return gas, withCode(regs, OOB), mem, ctxPair, nil
	}

	// (φ′7, µ′) = (OK, µ′o...o+z = s)
	err = mem.Write(o, s)
	if err != nil {
		return gas, regs, mem, ctxPair, ErrPanicf(err.Error())
	}

	return gas, withCode(regs, OK), mem, ctxPair, nil
}

// Poke ΩO(ϱ, φ, µ, (m, e))
func Poke(
	gas Gas,
	regs Registers,
	mem Memory,
	ctxPair RefineContextPair,
) (Gas, Registers, Memory, RefineContextPair, error) {
	if gas < PokeCost {
		return 0, regs, mem, ctxPair, ErrOutOfGas
	}
	gas -= PokeCost

	n, sReg, o, z := regs[A0], regs[A1], regs[A2], regs[A3]

	innerPVM, exists := ctxPair.IntegratedPVMMap[n]
	if !exists {
		//n ∉ K(m)
		return gas, withCode(regs, WHO), mem, ctxPair, nil
	}

	s := make([]byte, z)
	err := mem.Read(sReg, s)
	if err != nil {
		return gas, regs, mem, ctxPair, ErrPanicf(err.Error())
	}

	err = innerPVM.Ram.Write(o, s)
	if err != nil {
		return gas, withCode(regs, OOB), mem, ctxPair, nil
	}

	// (φ′7,m′) = (OK, (m′[n]u)[o..o+z]=s)
	ctxPair.IntegratedPVMMap[n] = innerPVM
	return gas, withCode(regs, OK), mem, ctxPair, nil
}

// Pages ΩZ (ϱ, φ, µ, (m, e))
func Pages(
	gas Gas,
	regs Registers,
	mem Memory,
	ctxPair RefineContextPair,
) (Gas, Registers, Memory, RefineContextPair, error) {
	if gas < PagesCost {
		return 0, regs, mem, ctxPair, ErrOutOfGas
	}
	gas -= PagesCost

	// let [n, p, c, r] = φ7⋅⋅⋅+4
	n, p, c, r := regs[A0], regs[A1], regs[A2], regs[A3]

	// m[n]u if n ∈ K(m);
	u, exists := ctxPair.IntegratedPVMMap[n]
	if !exists {
		//  ∇ otherwise
		return gas, withCode(regs, WHO), mem, ctxPair, nil
	}

	// if r > 4 ∨ p < 16 ∨ p + c ≥ 2^32/ZP
	if r > 4 || p < 16 || p+c >= MaxPageIndex {
		return gas, withCode(regs, HUH), mem, ctxPair, nil
	}

	// if r > 2 ∧ (uA)p⋅⋅⋅+c ∋ ∅
	if r > 2 {
		for pageIndex := p; pageIndex < p+c; pageIndex++ {
			if u.Ram.GetAccess(pageIndex) == Inaccessible {
				return gas, withCode(regs, HUH), mem, ctxPair, nil
			}
		}
	}

	// (u′V)pZP..+cZP = [0, 0, ...] if r < 3
	if r < 3 {
		for pageIndex := p; pageIndex < p+c; pageIndex++ {
			start := pageIndex * uint64(PageSize)
			zeroBuf := make([]byte, PageSize)
			if err := u.Ram.Write(start, zeroBuf); err != nil {
				return gas, regs, mem, ctxPair, err
			}
		}
	}

	// (u′A)p..+c = [∅|R|W,...]
	var newAccess MemoryAccess
	switch r {
	case 0:
		//[∅, ∅, ...]
		newAccess = Inaccessible
	case 1, 3:
		//[R, R, ...]
		newAccess = ReadOnly
	case 2, 4:
		//[W, W, ...]
		newAccess = ReadWrite
	default:
		return gas, withCode(regs, HUH), mem, ctxPair, nil
	}

	for pageIndex := p; pageIndex < p+c; pageIndex++ {
		if err := u.Ram.SetAccess(pageIndex, newAccess); err != nil {
			return gas, regs, mem, ctxPair, err
		}
	}

	// m′[n]u = u′
	ctxPair.IntegratedPVMMap[n] = u
	return gas, withCode(regs, OK), mem, ctxPair, nil
}

// Invoke ΩK(ϱ, φ, µ, (m, e))
func Invoke(
	gas Gas,
	regs Registers,
	mem Memory,
	ctxPair RefineContextPair,
) (Gas, Registers, Memory, RefineContextPair, error) {
	if gas < InvokeCost {
		return 0, regs, mem, ctxPair, ErrOutOfGas
	}
	gas -= InvokeCost
	// let [n, o] = φ7,8
	pvmKey, addr := regs[A0], regs[A1]

	// let (g, w) = (g, w) ∶ E8(g) ⌢ E#8(w) = μo⋅⋅⋅+112 if No⋅⋅⋅+112 ⊂ V∗μ
	invokeGas, err := readNumber[Gas](mem, addr, 8)
	if err != nil {
		return gas, regs, mem, ctxPair, ErrPanicf(err.Error())
	}
	var invokeRegs Registers // w
	for i := range 13 {
		invokeReg, err := readNumber[uint64](mem, addr+(uint64(i+1)*8), 8)
		if err != nil {
			return gas, regs, mem, ctxPair, ErrPanicf(err.Error())
		}
		invokeRegs[i] = invokeReg
	}

	// let (c, i′, g′, w′, u′) = Ψ(m[n]p, m[n]i, g, w, m[n]u)
	pvm, ok := ctxPair.IntegratedPVMMap[pvmKey]
	if !ok { // if n ∉ m
		return gas, withCode(regs, WHO), mem, ctxPair, nil // (WHO, φ8, μ, m)
	}
	updateIntegratedPVM := func(isHostCall bool, resultInstr uint64, resultMem Memory) {
		pvm.Ram = resultMem
		if isHostCall {
			// m*[n]i = i′ + 1 if c ∈ {̵h} × NR
			pvm.InstructionCounter = resultInstr + 1
		} else {
			// m*[n]i = i′
			pvm.InstructionCounter = resultInstr
		}
		ctxPair.IntegratedPVMMap[pvmKey] = pvm
	}

	i, err := interpreter.Instantiate(pvm.Code, pvm.InstructionCounter, invokeGas, invokeRegs, pvm.Ram)
	if err != nil {
		return gas, withCode(regs, PANIC), mem, ctxPair, nil
	}
	hostCall, invokeErr := interpreter.Invoke(i)
	resultInstr, resultGas, resultRegs, resultMem := i.Results()
	if bb, err := jam.Marshal([14]uint64(append([]uint64{uint64(resultGas)}, resultRegs[:]...))); err != nil {
		return gas, regs, mem, ctxPair, ErrPanicf(err.Error()) // (panic, φ8, μ, m)
	} else if err := mem.Write(addr, bb); err != nil {
		return gas, regs, mem, ctxPair, ErrPanicf(err.Error()) // (panic, φ8, μ, m)
	}
	if invokeErr != nil {
		if errors.Is(invokeErr, ErrOutOfGas) {
			updateIntegratedPVM(false, resultInstr, resultMem)
			return gas, withCode(regs, OOG), mem, ctxPair, nil // (OOG, φ8, μ*, m*)
		}
		if errors.Is(invokeErr, ErrHalt) {
			updateIntegratedPVM(false, resultInstr, resultMem)
			return gas, withCode(regs, HALT), mem, ctxPair, nil // (HALT, φ8, μ*, m*)
		}
		if errors.Is(invokeErr, ErrHostCall) {
			updateIntegratedPVM(true, resultInstr, resultMem)
			regs[A1] = uint64(hostCall)
			return gas, withCode(regs, HOST), mem, ctxPair, nil // (HOST, h, μ*, m*)
		}
		pageFault := &ErrPageFault{}
		if errors.As(invokeErr, &pageFault) {
			updateIntegratedPVM(false, resultInstr, resultMem)
			regs[A1] = uint64(pageFault.Address)
			return gas, withCode(regs, FAULT), mem, ctxPair, nil
		}
		panicErr := &ErrPanic{}
		if errors.As(invokeErr, &panicErr) {
			updateIntegratedPVM(false, resultInstr, resultMem)
			return gas, withCode(regs, PANIC), mem, ctxPair, nil
		}

		// must never occur
		panic(invokeErr)
	}

	updateIntegratedPVM(false, resultInstr, resultMem)
	return gas, withCode(regs, HALT), mem, ctxPair, nil // (HALT, φ8, μ*, m*)
}

// Expunge ΩX(ϱ, φ, µ, (m, e))
func Expunge(
	gas Gas,
	regs Registers,
	mem Memory,
	ctxPair RefineContextPair,
) (Gas, Registers, Memory, RefineContextPair, error) {
	if gas < ExpungeCost {
		return 0, regs, mem, ctxPair, ErrOutOfGas
	}
	gas -= ExpungeCost

	n := regs[A0]

	pvm, exists := ctxPair.IntegratedPVMMap[n]
	if !exists {
		return gas, withCode(regs, WHO), mem, ctxPair, nil
	}

	// (φ′7, m′) = (m[n]i, m ∖ n)
	regs[A0] = uint64(pvm.InstructionCounter)
	delete(ctxPair.IntegratedPVMMap, n)

	return gas, regs, mem, ctxPair, nil
}

func findSmallestMissingKey(m map[uint64]IntegratedPVM) uint64 {
	for n := uint64(0); ; n++ {
		if _, exists := m[n]; !exists {
			return n
		}
	}
}
