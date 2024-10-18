package host_call_test

import (
	"github.com/eigerco/strawberry/internal/block"
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/polkavm"
	"github.com/eigerco/strawberry/internal/polkavm/host_call"
	"github.com/eigerco/strawberry/internal/polkavm/interpreter"
	"github.com/eigerco/strawberry/internal/state"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/blake2b"
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

func TestLookup(t *testing.T) {
	pp := &polkavm.Program{
		RODataSize: 0,
		RWDataSize: 256,
		StackSize:  512,
	}

	memoryMap, err := polkavm.NewMemoryMap(
		polkavm.VmMinPageSize,
		pp.RODataSize,
		pp.RWDataSize,
		pp.StackSize,
		pp.ROData,
	)
	require.NoError(t, err)

	module, err := interpreter.NewModule(pp, memoryMap)
	require.NoError(t, err)

	initialGas := int64(100)

	// Service Not Found
	instance := module.Instantiate(0, initialGas)
	instance.SetReg(polkavm.A0, 1)

	err = host_call.Lookup(instance, memoryMap, 1, make(state.ServiceState))
	assert.NoError(t, err)
	assert.Equal(t, uint32(polkavm.HostCallResultNone), instance.GetReg(polkavm.A0))
	assert.Equal(t, initialGas-host_call.LookupCost, instance.GasRemaining())

	// Successful Key Lookup
	instance = module.Instantiate(0, 100)
	serviceId := block.ServiceId(1)
	val := []byte("value to store")

	ho := memoryMap.RWDataAddress
	bo := memoryMap.RWDataAddress + 100

	dataToHash := make([]byte, 32)
	copy(dataToHash, "hash")

	hash := blake2b.Sum256(dataToHash)

	serviceState := state.ServiceState{
		serviceId: state.ServiceAccount{
			Storage: map[crypto.Hash][]byte{
				hash: val,
			},
		},
	}

	err = instance.SetMemory(memoryMap, ho, dataToHash)
	require.NoError(t, err)

	// Set the registers
	instance.SetReg(polkavm.A0, uint32(serviceId))
	instance.SetReg(polkavm.A1, ho)
	instance.SetReg(polkavm.A2, bo)
	instance.SetReg(polkavm.A3, 32)

	// Perform the lookup
	err = host_call.Lookup(instance, memoryMap, serviceId, serviceState)
	assert.NoError(t, err)

	actualValue, err := instance.GetMemory(memoryMap, bo, len(val))
	require.NoError(t, err)

	assert.Equal(t, val, actualValue)
	assert.Equal(t, uint32(len(val)), instance.GetReg(polkavm.A0))
	assert.Equal(t, initialGas-host_call.LookupCost, instance.GasRemaining())
}
