package host_call

import (
	"github.com/eigerco/strawberry/internal/block"
	"github.com/eigerco/strawberry/internal/polkavm"
	"github.com/eigerco/strawberry/internal/state"
	"golang.org/x/crypto/blake2b"
	"math"
)

const (
	GasRemainingCost = 10
	LookupCost       = 10
)

// GasRemaining ΩG
func GasRemaining(instance polkavm.Instance) error {
	if err := deductGas(instance, GasRemainingCost); err != nil {
		return err
	}

	ksLower := instance.GetReg(polkavm.A0) // Lower 32 bits
	ksUpper := instance.GetReg(polkavm.A1) // Upper 32 bits

	// Combine the two parts into a single 64-bit value
	ks := (uint64(ksUpper) << 32) | uint64(ksLower)

	ks -= uint64(GasRemainingCost)

	// Split the new ξ' value into its lower and upper parts.
	instance.SetReg(polkavm.A0, uint32(ks&((1<<32)-1)))
	instance.SetReg(polkavm.A1, uint32(ks>>32))

	return nil
}

// Lookup ΩL
func Lookup(instance polkavm.Instance, memoryMap *polkavm.MemoryMap, serviceId block.ServiceId, serviceState state.ServiceState) error {
	if err := deductGas(instance, LookupCost); err != nil {
		return err
	}

	omega0 := instance.GetReg(polkavm.A0)

	// Determine the lookup key 'a'
	var a state.ServiceAccount
	if omega0 == uint32(serviceId) || omega0 == math.MaxUint32 {
		// Lookup service account by serviceId in the serviceState
		serviceAccount, serviceExists := serviceState[serviceId]
		if !serviceExists {
			instance.SetReg(polkavm.A0, uint32(polkavm.HostCallResultNone))
			return nil
		}

		a = serviceAccount
	} else {
		storedService, exists := serviceState[block.ServiceId(omega0)]
		if !exists {
			instance.SetReg(polkavm.A0, uint32(polkavm.HostCallResultNone))
			return nil
		}
		a = storedService
	}

	ho := instance.GetReg(polkavm.A1)

	// Ensure the memory range is valid for hashing (µho..ho+32)
	memorySlice, err := instance.GetMemory(memoryMap, ho, 32)
	if err != nil {
		instance.SetReg(polkavm.A0, uint32(polkavm.HostCallResultOob))
		return nil
	}

	// Compute the hash H(µho..ho+32)
	hash := blake2b.Sum256(memorySlice)

	// Lookup value in storage (v) using the hash
	v, exists := a.Storage[hash]
	if !exists {
		instance.SetReg(polkavm.A0, uint32(polkavm.HostCallResultNone))
		return nil
	}

	bo := instance.GetReg(polkavm.A2)
	bz := instance.GetReg(polkavm.A3)

	// Write value to memory if within bounds
	if len(v) > 0 && len(v) <= int(bz) {
		if err = instance.SetMemory(memoryMap, bo, v); err != nil {
			instance.SetReg(polkavm.A0, uint32(polkavm.HostCallResultOob))
			return nil
		}
	} else {
		instance.SetReg(polkavm.A0, uint32(polkavm.HostCallResultOob))
		return nil
	}

	instance.SetReg(polkavm.A0, uint32(len(v)))

	return nil
}

func deductGas(instance polkavm.Instance, gasCost int64) error {
	if instance.GasRemaining() < gasCost {
		return polkavm.ErrOutOfGas
	}

	instance.DeductGas(gasCost)

	return nil
}
