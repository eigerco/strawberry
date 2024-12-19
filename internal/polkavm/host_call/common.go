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
	QuitCost
	SolicitCost
	ForgetCost
	HistoricalLookupCost
	ImportCost
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
	QuitID
	SolicitID
	ForgetID
	HistoricalLookupID
	ImportID
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
	NONE Code = math.MaxUint64
	WHAT Code = math.MaxUint64 - 1
	OOB  Code = math.MaxUint64 - 2
	WHO  Code = math.MaxUint64 - 3
	FULL Code = math.MaxUint64 - 4
	CORE Code = math.MaxUint64 - 5
	CASH Code = math.MaxUint64 - 6
	LOW  Code = math.MaxUint64 - 7
	HIGH Code = math.MaxUint64 - 8
	HUH  Code = math.MaxUint64 - 9
	OK   Code = 0
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
	case HIGH:
		return "gas limit too high"
	case HUH:
		return "the item is already solicited or cannot be forgotten"
	case OK:
		return "success"
	}
	return "unknown"
}

func readNumber[U interface{ ~uint32 | ~uint64 }](mem Memory, addr uint32, length int) (u U, err error) {
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
