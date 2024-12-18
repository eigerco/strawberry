package host_call

import (
	"math"

	"github.com/eigerco/strawberry/internal/block"
	"github.com/eigerco/strawberry/internal/common"
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/jamtime"
	. "github.com/eigerco/strawberry/internal/polkavm"
	"github.com/eigerco/strawberry/internal/service"
	"github.com/eigerco/strawberry/internal/work"
)

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

	ho := regs[A1]
	bo := regs[A2]
	bz := regs[A3]

	hashData := make([]byte, 32)
	if err := mem.Read(uint32(ho), hashData); err != nil {
		return gas, withCode(regs, OOB), mem, ctxPair, err
	}

	// Compute hash H(µho..ho+32)
	h := crypto.HashData(hashData)

	// Compute v = Λ(a, t, h) using the provided LookupPreimage function
	v := a.LookupPreimage(t, h)

	if len(v) == 0 {
		return gas, withCode(regs, NONE), mem, ctxPair, nil
	}

	if uint64(len(v)) > bz {
		return gas, withCode(regs, OOB), mem, ctxPair, nil
	}

	if err := mem.Write(uint32(bo), v); err != nil {
		return gas, withCode(regs, OOB), mem, ctxPair, err
	}

	// set ω7 to |v|
	regs[A0] = uint64(len(v))

	return gas, regs, mem, ctxPair, nil
}

// Import ΩY(ϱ, ω, µ, (m, e), i)
func Import(
	gas Gas,
	regs Registers,
	mem Memory,
	ctxPair RefineContextPair,
	importedSegments []Segment,
) (Gas, Registers, Memory, RefineContextPair, error) {
	if gas < ImportCost {
		return gas, regs, mem, ctxPair, ErrOutOfGas
	}
	gas -= ImportCost

	index := regs[A0]  // ω7
	offset := regs[A1] // ω8
	length := regs[A2] // ω9

	// v = ∅
	if index >= uint64(len(importedSegments)) {
		// v = ∅, return NONE
		return gas, withCode(regs, NONE), mem, ctxPair, nil
	}

	// v = i[ω7]
	v := importedSegments[index][:]

	l := min(length, common.SizeOfSegment)

	segmentToWrite := v[:l]
	if err := mem.Write(uint32(offset), segmentToWrite); err != nil {
		return gas, withCode(regs, OOB), mem, ctxPair, nil
	}

	return gas, withCode(regs, OK), mem, ctxPair, nil
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
	if err := mem.Read(uint32(p), data); err != nil {
		// x = ∇
		return gas, withCode(regs, OOB), mem, ctxPair, nil
	}

	// Apply zero-padding Pn to data to make it WG-sized
	paddedData := work.ZeroPadding(data, common.SizeOfSegment)

	var segmentData Segment
	copy(segmentData[:], paddedData)

	currentCount := uint64(len(ctxPair.Segments))
	if exportOffset+currentCount >= work.MaxNumberOfEntries {
		return gas, withCode(regs, FULL), mem, ctxPair, nil
	}

	// Append x to e
	ctxPair.Segments = append(ctxPair.Segments, segmentData)

	// ω7 = ς + |e|
	regs[A0] = exportOffset + uint64(len(ctxPair.Segments))

	return gas, regs, mem, ctxPair, nil
}