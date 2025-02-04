package host_call

import (
	"math"

	. "github.com/eigerco/strawberry/internal/polkavm"
	"github.com/eigerco/strawberry/pkg/serialization/codec/jam"
)

const (
	GasRemainingCost Gas = 10
	LookupCost
	ReadCost
	WriteCost
	InfoCost
	BlessCost
	AssignCost
	DesignateCost
	CheckpointCost
	NewCost
	UpgradeCost
	TransferBaseCost
	EjectCost
	QueryCost
	SolicitCost
	ForgetCost
	YieldCost
	HistoricalLookupCost
	FetchCost
	ExportCost
	MachineCost
	PeekCost
	PokeCost
	ZeroCost
	VoidCost
	InvokeCost
	ExpungeCost
)

const (
	GasID = iota
	LookupID
	ReadID
	WriteID
	InfoID
	BlessID
	AssignID
	DesignateID
	CheckpointID
	NewID
	UpgradeID
	TransferID
	EjectID
	QueryID
	SolicitID
	ForgetID
	YieldID
	HistoricalLookupID
	FetchID
	ExportID
	MachineID
	PeekID
	PokeID
	ZeroID
	VoidID
	InvokeID
	ExpungeID
)

type Code uint64

const (
	NONE Code = math.MaxUint64 - iota
	WHAT
	OOB
	WHO
	FULL
	CORE
	CASH
	LOW
	HUH
	OK Code = 0
)

// Inner pvm invocations have their own set of result codes
const (
	HALT  = 0 // The invocation completed and halted normally.
	PANIC = 1 // The invocation completed with a panic.
	FAULT = 2 // The invocation completed with a page fault.
	HOST  = 3 // The invocation completed with a host-call fault.
	OOG   = 4 // The invocation completed by running out of gas.
)

func (r Code) String() string {
	switch r {
	case NONE:
		return "item does not exist"
	case WHAT:
		return "name unknown"
	case OOB:
		return "the return value for memory index provided is not accessible"
	case WHO:
		return "index unknown"
	case FULL:
		return "storage full"
	case CORE:
		return "core index unknown"
	case CASH:
		return "insufficient funds"
	case LOW:
		return "gas limit too low"
	case HUH:
		return "the item is already solicited or cannot be forgotten"
	case OK:
		return "success"
	}
	return "unknown"
}

func readNumber[U interface{ ~uint32 | ~uint64 | ~int64 }](mem Memory, addr uint32, length int) (u U, err error) {
	b := make([]byte, length)
	if err = mem.Read(addr, b); err != nil {
		return
	}

	err = jam.Unmarshal(b, &u)
	return
}

func withCode(regs Registers, s Code) Registers {
	regs[A0] = uint64(s)
	return regs
}
