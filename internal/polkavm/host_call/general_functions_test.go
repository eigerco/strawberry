package host_call_test

import (
	"github.com/eigerco/strawberry/internal/polkavm"
	"github.com/eigerco/strawberry/internal/polkavm/host_call"
	"github.com/eigerco/strawberry/internal/polkavm/interpreter"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestGasRemaining(t *testing.T) {
	pp := &polkavm.Program{
		RODataSize: 0,
		RWDataSize: 0,
		StackSize:  4096,
	}

	memoryMap, err := polkavm.NewMemoryMap(polkavm.VmMaxPageSize, pp.RODataSize, pp.RWDataSize, pp.StackSize, pp.ROData)
	require.NoError(t, err)

	module, err := interpreter.NewModule(pp, memoryMap)
	require.NoError(t, err)

	initialGas := int64(100)
	instance := module.Instantiate(0, initialGas)

	// Set the registers A0 and A1 to represent ξ
	instance.SetReg(polkavm.A0, uint32(initialGas&((1<<32)-1)))
	instance.SetReg(polkavm.A1, uint32(initialGas>>32))

	// Run the GasRemaining function
	err = host_call.GasRemaining(instance)
	assert.NoError(t, err)

	expectedGas := initialGas - host_call.GasRemainingCost

	assert.Equal(t, expectedGas, instance.GasRemaining())
	assert.Equal(t, expectedGas, (int64(instance.GetReg(polkavm.A1))<<32)|int64(instance.GetReg(polkavm.A0)))
}
