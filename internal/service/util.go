package service

import (
	"github.com/eigerco/strawberry/internal/block"
)

const (
	S     = 1 << 16 // The minimum public service index. Services of indices below these may only be created by the Registrar.
	bit8  = 1 << 8
	bit32 = 1 << 32
)

// BumpIndex produces a new service id using CheckIndex, it does
// check(S + (x_i - S + 42) mod (2^32 - S - 2^8)) from the new host call.
// See section B.7 (v0.7.1)
func BumpIndex(serviceIndex block.ServiceId, serviceState ServiceState) block.ServiceId {
	return CheckIndex(S+(serviceIndex-S+42)%(bit32-S-bit8), serviceState)
}

// CheckIndex Equation B.14 (v0.7.1): checks if the identifier is unique across all services
// and if not finds the first available one.
// check(i ∈ ℕ_S) =
// i                                                 if i ∉ K(e_d)
// check((i - S + 1) mod (2^32 - 2^8 - S) + S)       otherwise
func CheckIndex(serviceIndex block.ServiceId, serviceState ServiceState) block.ServiceId {
	if _, ok := serviceState[serviceIndex]; !ok {
		return serviceIndex
	}
	return CheckIndex((serviceIndex-S+1)%(bit32-bit8-S)+S, serviceState)
}

// DeriveIndex is a helper for producing a new service id during accumulation.
// See equation B.10 (v0.7.1)
// where i = check((ℰ_4^(-1)(ℋ(ℰ(s, η'_0, H_T))) mod (2^32 - S - 2^8)) + S)
// (ℰ_4^(-1)(ℋ(ℰ(s, η'_0, H_T)) is the serviceIndex passed in.
func DeriveIndex(serviceIndex block.ServiceId, serviceState ServiceState) block.ServiceId {
	return CheckIndex((serviceIndex%(bit32-S-bit8))+S, serviceState)
}
