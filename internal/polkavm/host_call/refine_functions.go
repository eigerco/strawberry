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

// HistoricalLookup ΩH(ϱ, ω, µ, (m, e), s, d, t)
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
		return gas, regs, mem, ctxPair, ErrOutOfGas
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

	// let [h, o] = ω8..+2
	addressToRead, addressToWrite := regs[A1], regs[A2]

	hashData := make([]byte, 32)
	if err := mem.Read(addressToRead, hashData); err != nil {
		return gas, regs, mem, ctxPair, ErrPanicf(err.Error())
	}

	// Compute v = Λ(a, t, h) using the provided LookupPreimage function
	v := a.LookupPreimage(t, crypto.Hash(hashData))

	if len(v) == 0 {
		return gas, withCode(regs, NONE), mem, ctxPair, nil
	}

	if err := writeFromOffset(mem, addressToWrite, v, regs[A3], regs[A4]); err != nil {
		return gas, regs, mem, ctxPair, err
	}

	// set ω7 to |v|
	regs[A0] = uint64(len(v))

	return gas, regs, mem, ctxPair, nil
}

// Fetch ΩY(ϱ, ω, µ, (m, e), i, p, o, i)
func Fetch(
	gas Gas,
	regs Registers,
	mem Memory,
	ctxPair RefineContextPair,
	itemIndex uint32,
	workPackage work.Package,
	authorizerHashOutput []byte,
	importedSegments []work.Segment,
	fetcher PreimageFetcher,
) (Gas, Registers, Memory, RefineContextPair, error) {
	if gas < FetchCost {
		return gas, regs, mem, ctxPair, ErrOutOfGas
	}
	gas -= FetchCost

	outputAddr := regs[A0] // o
	offset := regs[A1]     // f
	length := regs[A2]     // l
	dataID := regs[A3]     // ω10
	index1 := regs[A4]     // ω11
	index2 := regs[A5]     // ω12

	var v []byte

	switch dataID {
	case 0:
		// v = E(p)
		var err error
		v, err = jam.Marshal(workPackage)
		if err != nil {
			return gas, regs, mem, ctxPair, err
		}
	case 1:
		// v = o
		v = authorizerHashOutput
	case 2:
		// ω11 < ∣pw∣
		if int(index1) < len(workPackage.WorkItems) {
			// v = pw[ω11]y
			v = workPackage.WorkItems[index1].Payload
		}
	case 3:
		// TODO: implement fetch preimage (#169)

		// v = x if ω11 < ∣pw∣ ∧ ω12 < ∣pw[ω11]x∣
		if fetcher != nil && int(index1) < len(workPackage.WorkItems) && int(index2) < len(workPackage.WorkItems[index1].Extrinsics) {
			extrinsicPair := workPackage.WorkItems[index1].Extrinsics[index2]
			preimage, err := fetcher.FetchPreimage(extrinsicPair.Hash)
			if err != nil {
				return gas, regs, mem, ctxPair, err
			}

			v = preimage
		}
	case 4:
		// TODO:implement fetch preimage (#169)

		// v = x if ω11 < ∣pw[i]x∣
		if fetcher != nil && int(index1) < len(workPackage.WorkItems[itemIndex].Extrinsics) {
			extrinsicPair := workPackage.WorkItems[itemIndex].Extrinsics[index1]
			preimage, err := fetcher.FetchPreimage(extrinsicPair.Hash)
			if err != nil {
				return gas, regs, mem, ctxPair, err
			}
			v = preimage
		}
	case 5:
		// v = i[ω11]ω12 if ω11 < ∣i∣ ∧ ω12 < ∣i[ω11]∣
		if int(index1) < len(importedSegments) && int(index2) < len(importedSegments[index1]) {
			v = []byte{importedSegments[index1][index2]}
		}
	case 6:
		// v = i[i]ω11 if ω11 < ∣i[i]∣
		if int(itemIndex) < len(importedSegments) && int(index1) < len(importedSegments[itemIndex]) {
			//i[i]ω11
			v = []byte{importedSegments[itemIndex][index1]}
		}
	case 7:
		// v = p_p
		v = workPackage.Parameterization
	}

	if v == nil {
		// v = ∅
		return gas, withCode(regs, NONE), mem, ctxPair, nil
	}

	if err := writeFromOffset(mem, outputAddr, v, offset, length); err != nil {
		return gas, regs, mem, ctxPair, err
	}

	regs[A0] = uint64(len(v))

	return gas, regs, mem, ctxPair, nil
}

// Export ΩE(ϱ, ω, µ, (m, e), ς)
func Export(
	gas Gas,
	regs Registers,
	mem Memory,
	ctxPair RefineContextPair,
	exportOffset uint64,
) (Gas, Registers, Memory, RefineContextPair, error) {
	if gas < ExportCost {
		return gas, regs, mem, ctxPair, ErrOutOfGas
	}
	gas -= ExportCost

	p := regs[A0]               // ω7
	requestedLength := regs[A1] // ω8

	// let z = min(ω8,WG)
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
	if exportOffset+currentCount >= work.MaxNumberOfImportsExports {
		return gas, withCode(regs, FULL), mem, ctxPair, nil
	}

	// Append x to e
	ctxPair.Segments = append(ctxPair.Segments, segmentData)

	// ω7 = ς + |e|
	regs[A0] = exportOffset + uint64(len(ctxPair.Segments))

	return gas, regs, mem, ctxPair, nil
}

// Machine ΩM(ϱ, ω, µ, (m, e))
func Machine(
	gas Gas,
	regs Registers,
	mem Memory,
	ctxPair RefineContextPair,
) (Gas, Registers, Memory, RefineContextPair, error) {
	if gas < MachineCost {
		return gas, regs, mem, ctxPair, ErrOutOfGas
	}
	gas -= MachineCost

	// let [po, pz, i] = ω7...10
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

	// (ω′7,m′) = (n, m ∪ {n ↦ {p,u,i}})
	regs[A0] = n
	ctxPair.IntegratedPVMMap[n] = pvm

	return gas, regs, mem, ctxPair, nil
}

// Peek ΩP(ϱ, ω, µ, (m, e))
func Peek(
	gas Gas,
	regs Registers,
	mem Memory,
	ctxPair RefineContextPair,
) (Gas, Registers, Memory, RefineContextPair, error) {
	if gas < PeekCost {
		return gas, regs, mem, ctxPair, ErrOutOfGas
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

	// (ω′7, µ′) = (OK, µ′o...o+z = s)
	err = mem.Write(o, s)
	if err != nil {
		return gas, regs, mem, ctxPair, ErrPanicf(err.Error())
	}

	return gas, withCode(regs, OK), mem, ctxPair, nil
}

// Poke ΩO(ϱ, ω, µ, (m, e))
func Poke(
	gas Gas,
	regs Registers,
	mem Memory,
	ctxPair RefineContextPair,
) (Gas, Registers, Memory, RefineContextPair, error) {
	if gas < PokeCost {
		return gas, regs, mem, ctxPair, ErrOutOfGas
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

	// (ω′7,m′) = (OK, (m′[n]u)[o..o+z]=s)
	ctxPair.IntegratedPVMMap[n] = innerPVM
	return gas, withCode(regs, OK), mem, ctxPair, nil
}

// Zero ΩZ(ϱ, ω, µ, (m, e))
func Zero(
	gas Gas,
	regs Registers,
	mem Memory,
	ctxPair RefineContextPair,
) (Gas, Registers, Memory, RefineContextPair, error) {
	if gas < ZeroCost {
		return gas, regs, mem, ctxPair, ErrOutOfGas
	}
	gas -= ZeroCost

	n, p, c := regs[A0], regs[A1], regs[A2]

	// p < 16 ∨ p + c ≥  2^32 / ZP
	if p < 16 || p+c >= MaxPageIndex {
		return gas, withCode(regs, HUH), mem, ctxPair, nil
	}

	// u = m[n]u if n ∈ K(m), otherwise ∇
	u, exists := ctxPair.IntegratedPVMMap[n]
	if !exists {
		return gas, withCode(regs, WHO), mem, ctxPair, nil
	}

	for pageIndex := p; pageIndex < p+c; pageIndex++ {
		// (u′A)p..+c = [W, W, ...]
		if err := u.Ram.SetAccess(pageIndex, ReadWrite); err != nil {
			return gas, regs, mem, ctxPair, err
		}

		// (u′V)pZP..+cZP = [0, 0, ...]
		start := pageIndex * uint64(PageSize)
		zeroBuf := make([]byte, PageSize)
		if err := u.Ram.Write(start, zeroBuf); err != nil {
			return gas, regs, mem, ctxPair, err
		}
	}

	// (ω′7,m′) = (OK, (m′[n]u)=u′)
	ctxPair.IntegratedPVMMap[n] = u
	return gas, withCode(regs, OK), mem, ctxPair, nil
}

// Void ΩV(ϱ, ω, µ, (m, e))
func Void(
	gas Gas,
	regs Registers,
	mem Memory,
	ctxPair RefineContextPair,
) (Gas, Registers, Memory, RefineContextPair, error) {
	if gas < VoidCost {
		return gas, regs, mem, ctxPair, ErrOutOfGas
	}
	gas -= VoidCost

	n, p, c := regs[A0], regs[A1], regs[A2]

	u, exists := ctxPair.IntegratedPVMMap[n]
	if !exists {
		return gas, withCode(regs, WHO), mem, ctxPair, nil
	}

	// p < 16 ∨ p + c ≥  2^32 / ZP
	if p < 16 || p+c >= MaxPageIndex {
		return gas, withCode(regs, HUH), mem, ctxPair, nil
	}

	for pageIndex := p; pageIndex < p+c; pageIndex++ {
		if u.Ram.GetAccess(pageIndex) == Inaccessible {
			// ∃i ∈ N_{p..+c} : (uA)[i] = ∅
			return gas, withCode(regs, HUH), mem, ctxPair, nil
		}

		// (u′V)pZP..+cZP = [0, 0, ...]
		start := pageIndex * uint64(PageSize)
		zeroBuf := make([]byte, PageSize)
		if err := u.Ram.Write(start, zeroBuf); err != nil {
			return gas, regs, mem, ctxPair, err
		}
	}

	for pageIndex := p; pageIndex < p+c; pageIndex++ {
		// (u′A)p..+c = [∅, ∅, ...]
		if err := u.Ram.SetAccess(pageIndex, Inaccessible); err != nil {
			return gas, regs, mem, ctxPair, err
		}
	}

	// (ω′7,m′) = (OK, m′[n]u = u′)
	ctxPair.IntegratedPVMMap[n] = u
	return gas, withCode(regs, OK), mem, ctxPair, nil
}

// Invoke ΩK(ϱ, ω, µ, (m, e))
func Invoke(
	gas Gas,
	regs Registers,
	mem Memory,
	ctxPair RefineContextPair,
) (Gas, Registers, Memory, RefineContextPair, error) {
	if gas < InvokeCost {
		return gas, regs, mem, ctxPair, ErrOutOfGas
	}
	gas -= InvokeCost
	// let [n, o] = ω7,8
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
		return gas, withCode(regs, WHO), mem, ctxPair, nil // (WHO, ω8, μ, m)
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
		return gas, regs, mem, ctxPair, ErrPanicf(err.Error()) // (panic, ω8, μ, m)
	} else if err := mem.Write(addr, bb); err != nil {
		return gas, regs, mem, ctxPair, ErrPanicf(err.Error()) // (panic, ω8, μ, m)
	}
	if invokeErr != nil {
		if errors.Is(invokeErr, ErrOutOfGas) {
			updateIntegratedPVM(false, resultInstr, resultMem)
			return gas, withCode(regs, OOG), mem, ctxPair, nil // (OOG, ω8, μ*, m*)
		}
		if errors.Is(invokeErr, ErrHalt) {
			updateIntegratedPVM(false, resultInstr, resultMem)
			return gas, withCode(regs, HALT), mem, ctxPair, nil // (HALT, ω8, μ*, m*)
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
	return gas, withCode(regs, HALT), mem, ctxPair, nil // (HALT, ω8, μ*, m*)
}

// Expunge ΩX(ϱ, ω, µ, (m, e))
func Expunge(
	gas Gas,
	regs Registers,
	mem Memory,
	ctxPair RefineContextPair,
) (Gas, Registers, Memory, RefineContextPair, error) {
	if gas < ExpungeCost {
		return gas, regs, mem, ctxPair, ErrOutOfGas
	}
	gas -= ExpungeCost

	n := regs[A0]

	pvm, exists := ctxPair.IntegratedPVMMap[n]
	if !exists {
		return gas, withCode(regs, WHO), mem, ctxPair, nil
	}

	// (ω′7, m′) = (m[n]i, m ∖ n)
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
