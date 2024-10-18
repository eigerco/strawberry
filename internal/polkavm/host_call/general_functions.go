package host_call

import (
	"github.com/eigerco/strawberry/internal/polkavm"
)

const GasRemainingCost = 10

// GasRemaining ΩG
func GasRemaining(instance polkavm.Instance) error {
	if instance.GasRemaining() < GasRemainingCost {
		return polkavm.ErrOutOfGas
	}
	instance.DeductGas(GasRemainingCost)

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
