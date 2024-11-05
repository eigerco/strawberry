package pvmutil

import (
	"github.com/eigerco/strawberry/internal/block"
	"github.com/eigerco/strawberry/internal/service"
)

const (
	Bit8  = 1 << 8
	Bit9  = 1 << 9
	Bit32 = 1 << 32
)

// Bump where bump(i ∈ NS) = 2^8 + (i − 2^8 + 42) mod (2^32 − 2^9)
func Bump(i block.ServiceId) block.ServiceId {
	return (i-Bit8+42)%(Bit32-Bit9) + Bit8
}

// Check Equation 260: checks if the identifier is unique across all services
func Check(serviceIndex block.ServiceId, serviceState service.ServiceState) block.ServiceId {
	if _, ok := serviceState[serviceIndex]; !ok {
		return serviceIndex
	}

	return Check((serviceIndex-Bit8+1)%(Bit32-Bit9)+Bit8, serviceState)
}
