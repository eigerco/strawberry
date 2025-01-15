package service

import (
	"github.com/eigerco/strawberry/internal/block"
)

const (
	bit8  = 1 << 8
	bit9  = 1 << 9
	bit32 = 1 << 32
)

// BumpIndex where bump(i ∈ NS) = 2^8 + (i − 2^8 + 42) mod (2^32 − 2^9)
func BumpIndex(serviceIndex block.ServiceId) block.ServiceId {
	return (serviceIndex-bit8+42)%(bit32-bit9) + bit8
}

// CheckIndex Equation B.13 (v0.5.4): checks if the identifier is unique across all services
func CheckIndex(serviceIndex block.ServiceId, serviceState ServiceState) block.ServiceId {
	if _, ok := serviceState[serviceIndex]; !ok {
		return serviceIndex
	}

	return CheckIndex((serviceIndex-bit8+1)%(bit32-bit9)+bit8, serviceState)
}

func DeriveIndex(serviceIndex block.ServiceId, serviceState ServiceState) block.ServiceId {
	return CheckIndex((serviceIndex-(bit8)+1)%(bit32-bit9)+bit8, serviceState)
}
