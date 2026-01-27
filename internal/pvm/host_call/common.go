package host_call

import (
	"math"

	. "github.com/eigerco/strawberry/internal/pvm" //nolint:staticcheck // TODO: remove dot import
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
	ProvideCost
	HistoricalLookupCost
	FetchCost
	ExportCost
	MachineCost
	PeekCost
	PokeCost
	PagesCost
	InvokeCost
	ExpungeCost
	LogCost
	GrowHeapCost = 100
)

const (
	// General Functions
	GasID = iota
	GrowHeapID
	FetchID
	LookupID
	ReadID
	WriteID
	InfoID

	// Refine Functions
	HistoricalLookupID
	ExportID
	MachineID
	PeekID
	PokeID
	PagesID
	InvokeID
	ExpungeID

	// Accumulate Functions
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
	ProvideID

	LogID = 100
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

// HostCallName returns a human-readable name for a host call ID
func HostCallName(id uint64) string {
	switch id {
	case GasID:
		return "gas"
	case FetchID:
		return "fetch"
	case LookupID:
		return "lookup"
	case ReadID:
		return "read"
	case WriteID:
		return "write"
	case InfoID:
		return "info"
	case HistoricalLookupID:
		return "historical_lookup"
	case ExportID:
		return "export"
	case MachineID:
		return "machine"
	case PeekID:
		return "peek"
	case PokeID:
		return "poke"
	case PagesID:
		return "pages"
	case InvokeID:
		return "invoke"
	case ExpungeID:
		return "expunge"
	case BlessID:
		return "bless"
	case AssignID:
		return "assign"
	case DesignateID:
		return "designate"
	case CheckpointID:
		return "checkpoint"
	case NewID:
		return "new"
	case UpgradeID:
		return "upgrade"
	case TransferID:
		return "transfer"
	case EjectID:
		return "eject"
	case QueryID:
		return "query"
	case SolicitID:
		return "solicit"
	case ForgetID:
		return "forget"
	case YieldID:
		return "yield"
	case ProvideID:
		return "provide"
	case LogID:
		return "log"
	default:
		return "unknown"
	}
}

func readNumber[U interface{ ~uint32 | ~uint64 | ~int64 }](mem Memory, addr uint64, length int) (u U, err error) {
	b := make([]byte, length)
	if addr > math.MaxUint32 {
		return 0, ErrPanicf("inaccessible memory, address out of range")
	}
	if err = mem.Read(uint32(addr), b); err != nil {
		return
	}

	err = jam.Unmarshal(b, &u)
	return
}

func withCode(regs Registers, s Code) Registers {
	regs[A0] = uint64(s)
	return regs
}

func writeFromOffset(
	mem *Memory,
	addressToWrite uint64,
	data []byte,
	offset uint64,
	length uint64,
) error {
	vLen := uint64(len(data))

	f := min(offset, vLen)
	l := min(length, vLen-f)

	if l > 0 {
		sliceToWrite := data[f : f+l]
		if addressToWrite > math.MaxUint32 {
			return ErrPanicf("inaccessible memory, address out of range")
		}
		if err := mem.Write(uint32(addressToWrite), sliceToWrite); err != nil {
			return ErrPanicf("out-of-bounds write at address %d", addressToWrite)
		}
	}
	return nil
}
