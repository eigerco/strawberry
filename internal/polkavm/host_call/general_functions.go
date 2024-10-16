package host_call

import (
	"github.com/eigerco/strawberry/internal/polkavm"
)

const GasCost = 10

// GasRemaining ΩG
func GasRemaining(instance polkavm.Instance) error {
	if instance.GasRemaining() < GasCost {
		return polkavm.ErrOutOfGas
	}
	instance.DeductGas(GasCost)

	ksLower := instance.GetReg(polkavm.A0) // Lower 32 bits
	ksUpper := instance.GetReg(polkavm.A1) // Upper 32 bits

	// Combine the two parts into a single 64-bit value
	ks := (uint64(ksUpper) << 32) | uint64(ksLower)

	ks -= uint64(GasCost)

	// Split the new ξ' value into its lower and upper parts.
	instance.SetReg(polkavm.A0, uint32(ks&((1<<32)-1)))
	instance.SetReg(polkavm.A1, uint32(ks>>32))

	return nil
}
