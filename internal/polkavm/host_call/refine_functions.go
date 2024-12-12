package host_call

import (
	"math"

	"github.com/eigerco/strawberry/internal/block"
	"github.com/eigerco/strawberry/internal/common"
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/jamtime"
	. "github.com/eigerco/strawberry/internal/polkavm"
	"github.com/eigerco/strawberry/internal/service"
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
		regs[A0] = uint64(NONE)
		return gas, regs, mem, ctxPair, nil
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

	omega7 := regs[A0]
	omega8 := regs[A1]
	omega9 := regs[A2]

	// v = ∅
	if omega7 >= uint64(len(importedSegments)) {
		// v = ∅, return NONE
		regs[A0] = uint64(NONE)
		return gas, regs, mem, ctxPair, nil
	}

	// v = i[ω7]
	v := importedSegments[omega7][:]

	l := min(omega9, common.SizeOfSegment)

	segmentToWrite := v[:l]
	if err := mem.Write(uint32(omega8), segmentToWrite); err != nil {
		regs[A0] = uint64(OOB)
		return gas, regs, mem, ctxPair, nil
	}

	regs[A0] = uint64(OK)
	return gas, regs, mem, ctxPair, nil
}
