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
func GasRemaining(instance polkavm.Instance) (uint32, error) {
	if err := deductGas(instance, GasRemainingCost); err != nil {
		return 0, err
	}

	ksLower := instance.GetReg(polkavm.A0) // Lower 32 bits
	ksUpper := instance.GetReg(polkavm.A1) // Upper 32 bits

	// Combine the two parts into a single 64-bit value
	ks := (uint64(ksUpper) << 32) | uint64(ksLower)

	ks -= uint64(GasRemainingCost)

	// Split the new ξ' value into its lower and upper parts.
	omega0, omega1 := uint32(ks&((1<<32)-1)), uint32(ks>>32)
	instance.SetReg(polkavm.A1, omega1)

	return omega0, nil
}

// Lookup ΩL
func Lookup(instance polkavm.Instance) (uint32, error) {
	if err := deductGas(instance, LookupCost); err != nil {
		return 0, err
	}

	omega0 := instance.GetReg(polkavm.A0)
	hostCtx := instance.GetHostFuncContext()

	// Determine the lookup key 'a'
	var a state.ServiceAccount
	if omega0 == uint32(hostCtx.ServiceId) || omega0 == math.MaxUint32 {
		// Lookup service account by serviceId in the serviceState
		serviceAccount, serviceExists := hostCtx.ServiceState[hostCtx.ServiceId]
		if !serviceExists {
			return uint32(polkavm.HostCallResultNone), nil
		}

		a = serviceAccount
	} else {
		storedService, exists := hostCtx.ServiceState[block.ServiceId(omega0)]
		if !exists {
			return uint32(polkavm.HostCallResultNone), nil
		}
		a = storedService
	}

	ho := instance.GetReg(polkavm.A1)

	// Ensure the memory range is valid for hashing (µho..ho+32)
	memorySlice, err := instance.GetMemory(hostCtx.MemoryMap, ho, 32)
	if err != nil {
		return uint32(polkavm.HostCallResultOob), nil
	}

	// Compute the hash H(µho..ho+32)
	hash := blake2b.Sum256(memorySlice)

	// Lookup value in storage (v) using the hash
	v, exists := a.Storage[hash]
	if !exists {
		return uint32(polkavm.HostCallResultNone), nil
	}

	bo := instance.GetReg(polkavm.A2)
	bz := instance.GetReg(polkavm.A3)

	// Write value to memory if within bounds
	if len(v) > 0 && len(v) <= int(bz) {
		if err = instance.SetMemory(hostCtx.MemoryMap, bo, v); err != nil {
			return uint32(polkavm.HostCallResultOob), nil
		}
	} else {
		return uint32(polkavm.HostCallResultOob), nil
	}

	return uint32(len(v)), nil
}

func deductGas(instance polkavm.Instance, gasCost int64) error {
	if instance.GasRemaining() < gasCost {
		return polkavm.ErrOutOfGas
	}

	instance.DeductGas(gasCost)

	return nil
}
