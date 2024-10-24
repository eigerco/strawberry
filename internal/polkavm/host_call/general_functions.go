package host_call

import (
	"github.com/eigerco/strawberry/internal/block"
	"github.com/eigerco/strawberry/internal/polkavm"
	"github.com/eigerco/strawberry/internal/state"
	"github.com/eigerco/strawberry/pkg/serialization"
	"github.com/eigerco/strawberry/pkg/serialization/codec"
	"golang.org/x/crypto/blake2b"
	"math"
)

const (
	GasRemainingCost = 10
	LookupCost
	ReadCost
	WriteCost
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

// MakeLookupFunc ΩL
func MakeLookupFunc(serviceId block.ServiceId, serviceState state.ServiceState, memoryMap *polkavm.MemoryMap) polkavm.HostFunc {
	return func(instance polkavm.Instance) (uint32, error) {
		if err := deductGas(instance, LookupCost); err != nil {
			return 0, err
		}

		sID := instance.GetReg(polkavm.A0)

		if sID == math.MaxUint32 {
			sID = uint32(serviceId)
		}

		//  account 'a'
		a, exists := serviceState[block.ServiceId(sID)]
		if !exists {
			return 0, polkavm.ErrAccountNotFound
		}

		ho := instance.GetReg(polkavm.A1)

		// Ensure the memory range is valid for hashing (µho..ho+32)
		memorySlice, err := instance.GetMemory(memoryMap, ho, 32)
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
			if err = instance.SetMemory(memoryMap, bo, v); err != nil {
				return uint32(polkavm.HostCallResultOob), nil
			}
		} else {
			return uint32(polkavm.HostCallResultOob), nil
		}

		return uint32(len(v)), nil
	}
}

// MakeReadFunc ΩR
func MakeReadFunc(serviceId block.ServiceId, serviceState state.ServiceState, memoryMap *polkavm.MemoryMap) polkavm.HostFunc {
	return func(instance polkavm.Instance) (uint32, error) {
		if err := deductGas(instance, ReadCost); err != nil {
			return 0, err
		}

		sID := instance.GetReg(polkavm.A0)
		ko := instance.GetReg(polkavm.A1)
		kz := instance.GetReg(polkavm.A2)
		bo := instance.GetReg(polkavm.A3)
		bz := instance.GetReg(polkavm.A4)

		if sID == math.MaxUint32 {
			sID = uint32(serviceId)
		}

		//  account 'a'
		storedService, exists := serviceState[block.ServiceId(sID)]
		if !exists {
			return 0, polkavm.ErrAccountNotFound
		}

		// read key data from memory at ko..ko+kz
		keyData, err := instance.GetMemory(memoryMap, ko, int(kz))
		if err != nil {
			return uint32(polkavm.HostCallResultOob), nil
		}

		serializer := serialization.NewSerializer(codec.NewJamCodec())
		serviceIdBytes, err := serializer.Encode(sID)
		if err != nil {
			return 0, err
		}

		// Concatenate E4(s) and keyData
		hashInput := make([]byte, 0, len(serviceIdBytes)+len(keyData))
		hashInput = append(hashInput, serviceIdBytes...)
		hashInput = append(hashInput, keyData...)

		// Compute the hash H(E4(s) + keyData)
		k := blake2b.Sum256(hashInput)

		v, exists := storedService.Storage[k]
		if !exists {
			return uint32(polkavm.HostCallResultNone), nil
		}

		writeLen := int(math.Min(float64(bz), float64(len(v))))

		if writeLen > 0 {
			if _, err = instance.GetMemory(memoryMap, bo, writeLen); err != nil {
				return uint32(polkavm.HostCallResultOob), nil
			}

			if err = instance.SetMemory(memoryMap, bo, v[:writeLen]); err != nil {
				return uint32(polkavm.HostCallResultOob), nil
			}

			return uint32(len(v)), nil
		}

		return uint32(polkavm.HostCallResultNone), nil
	}
}

// MakeWriteFunc ΩW
func MakeWriteFunc(serviceId block.ServiceId, serviceState state.ServiceState, memoryMap *polkavm.MemoryMap) polkavm.HostFunc {
	return func(instance polkavm.Instance) (uint32, error) {
		if err := deductGas(instance, WriteCost); err != nil {
			return 0, err
		}

		ko := instance.GetReg(polkavm.A0)
		kz := instance.GetReg(polkavm.A1)
		vo := instance.GetReg(polkavm.A2)
		vz := instance.GetReg(polkavm.A3)

		var l uint32

		keyData, err := instance.GetMemory(memoryMap, ko, int(kz))
		if err != nil {
			return 0, err
		}

		serializer := serialization.NewSerializer(codec.NewJamCodec())
		serviceIdBytes, err := serializer.Encode(serviceId)
		if err != nil {
			return 0, err
		}
		hashInput := append(serviceIdBytes, keyData...)
		k := blake2b.Sum256(hashInput)

		a, accountExists := serviceState[serviceId]
		if !accountExists {
			return 0, polkavm.ErrAccountNotFound
		}

		v, keyExists := a.Storage[k]
		if !keyExists {
			return uint32(polkavm.HostCallResultNone), nil
		}

		l = uint32(len(v))

		if vz == 0 {
			delete(a.Storage, k)
		} else {
			availableMemory := memoryMap.RWDataAddress + memoryMap.RWDataSize - vo
			if availableMemory < vz {
				return uint32(polkavm.HostCallResultFull), nil
			}

			valueData, err := instance.GetMemory(memoryMap, vo, int(vz))
			if err != nil {
				return uint32(polkavm.HostCallResultOob), nil
			}

			a.Storage[k] = valueData
		}

		serviceState[serviceId] = a
		return l, nil
	}
}

func deductGas(instance polkavm.Instance, gasCost int64) error {
	if instance.GasRemaining() < gasCost {
		return polkavm.ErrOutOfGas
	}

	instance.DeductGas(gasCost)

	return nil
}
