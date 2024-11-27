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
)

const (
	GasID        = 0
	LookupID     = 1
	ReadID       = 2
	WriteID      = 3
	InfoID       = 4
	BlessID      = 5
	AssignID     = 6
	DesignateID  = 7
	CheckpointID = 8
	NewID        = 9
	UpgradeID    = 10
	TransferID   = 11
	QuitID       = 12
	SolicitID    = 13
	ForgetID     = 14
)

type Code uint32

const (
	NONE Code = math.MaxUint32
	WHAT Code = math.MaxUint32 - 1
	OOB  Code = math.MaxUint32 - 2
	WHO  Code = math.MaxUint32 - 3
	FULL Code = math.MaxUint32 - 4
	CORE Code = math.MaxUint32 - 5
	CASH Code = math.MaxUint32 - 6
	LOW  Code = math.MaxUint32 - 7
	HIGH Code = math.MaxUint32 - 8
	HUH  Code = math.MaxUint32 - 9
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
	regs[A0] = uint32(s)
	return regs
}
