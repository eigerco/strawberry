package host_call

import (
	"math"

	"github.com/eigerco/strawberry/internal/block"
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/polkavm"
	"github.com/eigerco/strawberry/internal/service"
	"github.com/eigerco/strawberry/pkg/serialization/codec/jam"
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

// GasRemaining ΩG(ϱ, ω, ...)
func GasRemaining(gas polkavm.Gas, regs polkavm.Registers) (polkavm.Gas, polkavm.Registers, error) {
	if gas < GasRemainingCost {
		return gas, regs, polkavm.ErrOutOfGas
	}
	gas -= GasRemainingCost

	// Set the new ϱ' value into ω′7
	regs[polkavm.A0] = uint64(gas)

	return gas, regs, nil
}

// Lookup ΩL(ϱ, ω, μ, s, s, d)
func Lookup(gas polkavm.Gas, regs polkavm.Registers, mem polkavm.Memory, s service.ServiceAccount, serviceId block.ServiceId, serviceState service.ServiceState) (polkavm.Gas, polkavm.Registers, polkavm.Memory, error) {
	if gas < LookupCost {
		return gas, regs, mem, polkavm.ErrOutOfGas
	}
	gas -= LookupCost

	omega7 := regs[polkavm.A0]

	// Determine the lookup key 'a'
	a := s
	if uint64(omega7) != math.MaxUint64 && omega7 != uint64(serviceId) {
		var exists bool
		// lookup service account by serviceId in the serviceState
		a, exists = serviceState[serviceId]
		if !exists {
			regs[polkavm.A0] = uint64(NONE)
			return gas, regs, mem, nil
		}
	}

	// let [h, o] = ω8..+2
	h, o := regs[polkavm.A1], regs[polkavm.A2]

	key := make([]byte, 32)
	if err := mem.Read(h, key); err != nil {
		return gas, regs, mem, polkavm.ErrPanicf(err.Error())
	}

	// lookup value in storage (v) using the hash
	v, exists := a.PreimageLookup[crypto.Hash(key)]
	if !exists {
		// v=∅ => (▸, NONE, μ)
		return gas, withCode(regs, NONE), mem, nil
	}

	if err := writeFromOffset(mem, o, v, regs[polkavm.A3], regs[polkavm.A4]); err != nil {
		return gas, regs, mem, err
	}

	regs[polkavm.A0] = uint64(len(v))
	return gas, regs, mem, nil
}

// Read ΩR(ϱ, ω, μ, s, s, d)
func Read(gas polkavm.Gas, regs polkavm.Registers, mem polkavm.Memory, s service.ServiceAccount, serviceId block.ServiceId, serviceState service.ServiceState) (polkavm.Gas, polkavm.Registers, polkavm.Memory, error) {
	if gas < ReadCost {
		return gas, regs, mem, polkavm.ErrOutOfGas
	}
	gas -= ReadCost

	omega7 := regs[polkavm.A0]
	// s* = ω7
	ss := block.ServiceId(omega7)
	if uint64(omega7) == math.MaxUint64 {
		ss = serviceId // s* = s
	}

	a := s
	if ss != serviceId {
		var exists bool
		a, exists = serviceState[ss]
		if !exists {
			return gas, regs, mem, polkavm.ErrAccountNotFound
		}
	}

	// let [ko, kz, o] = ω8..+3
	ko, kz, o := regs[polkavm.A1], regs[polkavm.A2], regs[polkavm.A3]

	// read key data from memory at ko..ko+kz
	keyData := make([]byte, kz)
	err := mem.Read(ko, keyData)
	if err != nil {
		return gas, regs, mem, polkavm.ErrPanicf(err.Error())
	}

	// k = H(E4(s*) ⌢ µko..ko+kz)
	serviceIdBytes, err := jam.Marshal(ss)
	if err != nil {
		return gas, regs, mem, polkavm.ErrPanicf(err.Error())
	}

	// Concatenate E4(s) and keyData
	hashInput := make([]byte, 0, len(serviceIdBytes)+len(keyData))
	hashInput = append(hashInput, serviceIdBytes...)
	hashInput = append(hashInput, keyData...)

	// Compute the hash H(E4(s) + keyData)
	k := crypto.HashData(hashInput)

	v, exists := a.Storage[k]
	if !exists {
		return gas, withCode(regs, NONE), mem, nil
	}

	if err = writeFromOffset(mem, o, v, regs[polkavm.A4], regs[polkavm.A5]); err != nil {
		return gas, regs, mem, err
	}

	regs[polkavm.A0] = uint64(len(v))
	return gas, regs, mem, nil
}

// Write ΩW(ϱ, ω, μ, s, s)
func Write(gas polkavm.Gas, regs polkavm.Registers, mem polkavm.Memory, s service.ServiceAccount, serviceId block.ServiceId) (polkavm.Gas, polkavm.Registers, polkavm.Memory, service.ServiceAccount, error) {
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
		return gas, regs, mem, s, polkavm.ErrPanicf(err.Error())
	}

	serviceIdBytes, err := jam.Marshal(serviceId)
	if err != nil {
		return gas, regs, mem, s, polkavm.ErrPanicf(err.Error())
	}
	hashInput := append(serviceIdBytes, keyData...)
	k := crypto.HashData(hashInput)

	a := s
	if vz == 0 {
		delete(a.Storage, k)
	} else {
		valueData := make([]byte, vz)
		err = mem.Read(vo, valueData)
		if err != nil {
			return gas, regs, mem, s, polkavm.ErrPanicf(err.Error())
		}

		a.Storage[k] = valueData
	}

	storageItem, ok := s.Storage[k]
	if !ok {
		return gas, withCode(regs, NONE), mem, s, err
	}

	if a.ThresholdBalance() > a.Balance {
		return gas, withCode(regs, FULL), mem, s, nil
	}

	// otherwise a.ThresholdBalance() <= a.Balance
	regs[polkavm.A0] = uint64(len(storageItem)) // l
	return gas, regs, mem, a, err               // return service account 'a' as opposed to 's' for not successful paths
}

// Info ΩI(ϱ, ω, μ, s, d)
func Info(gas polkavm.Gas, regs polkavm.Registers, mem polkavm.Memory, serviceId block.ServiceId, serviceState service.ServiceState) (polkavm.Gas, polkavm.Registers, polkavm.Memory, error) {
	if gas < InfoCost {
		return gas, regs, mem, polkavm.ErrOutOfGas
	}
	gas -= InfoCost

	omega7 := regs[polkavm.A0]
	omega8 := regs[polkavm.A1]

	t, exists := serviceState[serviceId]
	if uint64(omega7) != math.MaxUint64 {
		t, exists = serviceState[block.ServiceId(omega7)]
	}
	if !exists {
		return gas, withCode(regs, NONE), mem, nil
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

	// E(tc, tb, tt, tg , tm, tl, ti)
	m, err := jam.Marshal(accountInfo)
	if err != nil {
		return gas, regs, mem, err
	}

	if err = mem.Write(omega8, m); err != nil {
		return gas, regs, mem, polkavm.ErrPanicf(err.Error())
	}

	return gas, withCode(regs, OK), mem, nil
}
