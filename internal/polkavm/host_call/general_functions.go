package host_call

import (
	"github.com/eigerco/strawberry/pkg/serialization"
	"github.com/eigerco/strawberry/pkg/serialization/codec"
	"math"

	"golang.org/x/crypto/blake2b"

	"github.com/eigerco/strawberry/internal/block"
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/polkavm"
	"github.com/eigerco/strawberry/internal/state"
)

const (
	GasRemainingCost polkavm.Gas = 10
	LookupCost
	ReadCost
	WriteCost
	InfoCost
)

type AccountInfo struct {
	CodeHash               crypto.Hash // tc
	Balance                uint64      // tb
	ThresholdBalance       uint64      // tt
	GasLimitForAccumulator uint64      // tg
	GasLimitOnTransfer     uint64      // tm
	TotalStorageSize       uint64      // tl
	TotalItems             uint32      // ti
}

// GasRemaining ΩG
func GasRemaining(gas polkavm.Gas, regs polkavm.Registers) (polkavm.Gas, polkavm.Registers, error) {
	if gas < GasRemainingCost {
		return gas, regs, polkavm.ErrOutOfGas
	}
	gas -= GasRemainingCost

	// Split the new ξ' value into its lower and upper parts.
	regs[polkavm.A0] = uint32(gas & ((1 << 32) - 1))
	regs[polkavm.A1] = uint32(gas >> 32)

	return gas, regs, nil
}

// Lookup ΩL
func Lookup(gas polkavm.Gas, regs polkavm.Registers, mem polkavm.Memory, serviceId block.ServiceId, serviceState state.ServiceState) (polkavm.Gas, polkavm.Registers, polkavm.Memory, error) {
	if gas < LookupCost {
		return gas, regs, mem, polkavm.ErrOutOfGas
	}
	gas -= LookupCost

	sID := regs[polkavm.A0]

	// Determine the lookup key 'a'
	var a state.ServiceAccount
	if sID == uint32(serviceId) || sID == math.MaxUint32 {
		// Lookup service account by serviceId in the serviceState
		serviceAccount, serviceExists := serviceState[serviceId]
		if !serviceExists {
			regs[polkavm.A0] = uint32(polkavm.HostCallResultNone)
			return gas, regs, mem, nil
		}

		a = serviceAccount
	} else {
		storedService, exists := serviceState[block.ServiceId(sID)]
		if !exists {
			regs[polkavm.A0] = uint32(polkavm.HostCallResultNone)
			return gas, regs, mem, nil
		}
		a = storedService
	}

	ho := regs[polkavm.A1]

	// Ensure the memory range is valid for hashing (µho..ho+32)
	memorySlice := make([]byte, 32)
	err := mem.Read(ho, memorySlice)
	if err != nil {
		regs[polkavm.A0] = uint32(polkavm.HostCallResultOob)
		return gas, regs, mem, err
	}

	// Compute the hash H(µho..ho+32)
	hash := blake2b.Sum256(memorySlice)

	// Lookup value in storage (v) using the hash
	v, exists := a.Storage[hash]
	if !exists {
		regs[polkavm.A0] = uint32(polkavm.HostCallResultNone)
		return gas, regs, mem, nil
	}

	bo := regs[polkavm.A2]
	bz := regs[polkavm.A3]

	// Write value to memory if within bounds
	if len(v) > 0 && len(v) <= int(bz) {
		if err = mem.Write(bo, v); err != nil {
			regs[polkavm.A0] = uint32(polkavm.HostCallResultOob)
			return gas, regs, mem, err
		}
	} else {
		regs[polkavm.A0] = uint32(polkavm.HostCallResultOob)
		return gas, regs, mem, err
	}

	regs[polkavm.A0] = uint32(len(v))
	return gas, regs, mem, err
}

// Read ΩR
func Read(gas polkavm.Gas, regs polkavm.Registers, mem polkavm.Memory, serviceId block.ServiceId, serviceState state.ServiceState) (polkavm.Gas, polkavm.Registers, polkavm.Memory, error) {
	if gas < ReadCost {
		return gas, regs, mem, polkavm.ErrOutOfGas
	}
	gas -= ReadCost

	sID := regs[polkavm.A0]
	ko := regs[polkavm.A1]
	kz := regs[polkavm.A2]
	bo := regs[polkavm.A3]
	bz := regs[polkavm.A4]

	if sID == math.MaxUint32 {
		sID = uint32(serviceId)
	}

	//  account 'a'
	storedService, exists := serviceState[block.ServiceId(sID)]
	if !exists {
		return gas, regs, mem, polkavm.ErrAccountNotFound
	}

	// read key data from memory at ko..ko+kz
	keyData := make([]byte, kz)
	err := mem.Read(ko, keyData)
	if err != nil {
		regs[polkavm.A0] = uint32(polkavm.HostCallResultOob)
		return gas, regs, mem, nil
	}

	serializer := serialization.NewSerializer(codec.NewJamCodec())
	serviceIdBytes, err := serializer.Encode(sID)
	if err != nil {
		return gas, regs, mem, polkavm.ErrPanicf(err.Error())
	}

	// Concatenate E4(s) and keyData
	hashInput := make([]byte, 0, len(serviceIdBytes)+len(keyData))
	hashInput = append(hashInput, serviceIdBytes...)
	hashInput = append(hashInput, keyData...)

	// Compute the hash H(E4(s) + keyData)
	k := blake2b.Sum256(hashInput)

	v, exists := storedService.Storage[k]
	if !exists {
		regs[polkavm.A0] = uint32(polkavm.HostCallResultNone)
		return gas, regs, mem, nil
	}

	writeLen := int(math.Min(float64(bz), float64(len(v))))

	if writeLen > 0 {
		if err = mem.Write(bo, v[:writeLen]); err != nil {
			regs[polkavm.A0] = uint32(polkavm.HostCallResultOob)
			return gas, regs, mem, nil
		}

		regs[polkavm.A0] = uint32(len(v))
		return gas, regs, mem, nil
	}

	regs[polkavm.A0] = uint32(polkavm.HostCallResultNone)
	return gas, regs, mem, nil
}

// Write ΩW
func Write(gas polkavm.Gas, regs polkavm.Registers, mem polkavm.Memory, serviceId block.ServiceId, s state.ServiceAccount) (polkavm.Gas, polkavm.Registers, polkavm.Memory, state.ServiceAccount, error) {
	if gas < WriteCost {
		return gas, regs, mem, s, polkavm.ErrOutOfGas
	}
	gas -= WriteCost

	ko := regs[polkavm.A0]
	kz := regs[polkavm.A1]
	vo := regs[polkavm.A2]
	vz := regs[polkavm.A3]

	keyData := make([]byte, kz)
	err := mem.Read(ko, keyData)
	if err != nil {
		return gas, regs, mem, s, err
	}

	serializer := serialization.NewSerializer(codec.NewJamCodec())
	serviceIdBytes, err := serializer.Encode(serviceId)
	if err != nil {
		return gas, regs, mem, s, err
	}
	hashInput := append(serviceIdBytes, keyData...)
	k := blake2b.Sum256(hashInput)

	a := s
	if vz == 0 {
		delete(a.Storage, k)
	} else {
		valueData := make([]byte, vz)
		err := mem.Read(vo, valueData)
		if err != nil {
			regs[polkavm.A0] = uint32(polkavm.HostCallResultOob)
			return gas, regs, mem, s, err
		}

		a.Storage[k] = valueData
	}

	storageItem, ok := s.Storage[k]
	if !ok {
		regs[polkavm.A0] = uint32(polkavm.HostCallResultNone)
		return gas, regs, mem, s, err
	}

	if a.ThresholdBalance() > a.Balance {
		regs[polkavm.A0] = uint32(polkavm.HostCallResultFull)
		return gas, regs, mem, s, err
	}

	// otherwise a.ThresholdBalance() <= a.Balance
	regs[polkavm.A0] = uint32(len(storageItem)) // l
	return gas, regs, mem, a, err               // return service account 'a' as opposed to 's' for not successful paths
}

func MakeInfoFunc(
	serviceId block.ServiceId,
	serviceState state.ServiceState,
	memoryMap *polkavm.MemoryMap,
) polkavm.HostFunc {
	return func(instance polkavm.Instance) (uint32, error) {
		if err := deductGas(instance, InfoCost); err != nil {
			return 0, err
		}

		sID := instance.GetReg(polkavm.A0)
		omega1 := instance.GetReg(polkavm.A1)

		if sID == math.MaxUint32 {
			sID = uint32(serviceId)
		}

		t, exists := serviceState[block.ServiceId(sID)]
		if !exists {
			return uint32(polkavm.HostCallResultNone), nil
		}

		accountInfo := AccountInfo{
			CodeHash:               t.CodeHash,
			Balance:                t.Balance,
			ThresholdBalance:       t.ThresholdBalance(),
			GasLimitForAccumulator: t.GasLimitForAccumulator,
			GasLimitOnTransfer:     t.GasLimitOnTransfer,
			TotalStorageSize:       t.TotalStorageSize(),
			TotalItems:             t.TotalItems(),
		}

		serializer := serialization.NewSerializer(codec.NewJamCodec())
		// E(tc, tb, tt, tg , tm, tl, ti)
		m, err := serializer.Encode(accountInfo)
		if err != nil {
			return 0, err
		}

		end := omega1 + uint32(len(m))
		if end > memoryMap.RWDataAddress+memoryMap.RWDataSize {
			return uint32(polkavm.HostCallResultOob), nil
		}

		err = instance.SetMemory(memoryMap, omega1, m)
		if err != nil {
			return uint32(polkavm.HostCallResultOob), nil
		}

		return uint32(polkavm.HostCallResultOk), nil
	}
}

func deductGas(instance polkavm.Instance, gasCost int64) error {
	if instance.GasRemaining() < gasCost {
		return polkavm.ErrOutOfGas
	}

	instance.DeductGas(gasCost)

	return nil
}
