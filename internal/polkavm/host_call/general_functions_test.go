package host_call_test

import (
	"github.com/eigerco/strawberry/internal/block"
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/polkavm"
	"github.com/eigerco/strawberry/internal/polkavm/host_call"
	"github.com/eigerco/strawberry/internal/polkavm/interpreter"
	"github.com/eigerco/strawberry/internal/state"
	"github.com/eigerco/strawberry/pkg/serialization"
	"github.com/eigerco/strawberry/pkg/serialization/codec"
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
		Instructions: []polkavm.Instruction{
			{Opcode: polkavm.Ecalli, Imm: []uint32{0}, Offset: 0, Length: 1},
			{Opcode: polkavm.JumpIndirect, Imm: []uint32{0}, Reg: []polkavm.Reg{polkavm.RA}, Offset: 3, Length: 2},
		},
		Imports: []string{"gas_remaining"},
		Exports: []polkavm.ProgramExport{{TargetCodeOffset: 0, Symbol: "test_gas"}},
	}

	memoryMap, err := polkavm.NewMemoryMap(polkavm.VmMaxPageSize, pp.RODataSize, pp.RWDataSize, pp.StackSize, pp.ROData)
	require.NoError(t, err)

	module, err := interpreter.NewModule(pp, memoryMap)
	require.NoError(t, err)

	module.AddHostFunc("gas_remaining", host_call.GasRemaining)

	initialGas := int64(100)

	_, instance, err := module.Run("test_gas", initialGas, nil, uint32(initialGas&((1<<32)-1)), uint32(initialGas>>32))
	require.NoError(t, err)

	expectedGas := initialGas - host_call.GasRemainingCost

	assert.Equal(t, expectedGas, (int64(instance.GetReg(polkavm.A1))<<32)|int64(instance.GetReg(polkavm.A0)))
}

func TestLookup(t *testing.T) {
	pp := &polkavm.Program{
		RODataSize: 0,
		RWDataSize: 256,
		StackSize:  512,
		Instructions: []polkavm.Instruction{
			{Opcode: polkavm.Ecalli, Imm: []uint32{0}, Offset: 0, Length: 1},
			{Opcode: polkavm.JumpIndirect, Imm: []uint32{0}, Reg: []polkavm.Reg{polkavm.RA}, Offset: 3, Length: 2},
		},
		Imports: []string{"lookup"},
		Exports: []polkavm.ProgramExport{{TargetCodeOffset: 0, Symbol: "test_lookup"}},
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
	module.AddHostFunc("lookup", host_call.MakeLookupFunc(1, make(state.ServiceState), memoryMap))

	// Service Not Found
	_, instance, err := module.Run("test_lookup", initialGas, nil, uint32(1))
	require.Error(t, err)

	// only one instruction executed before error
	assert.Equal(t, initialGas-host_call.LookupCost-int64(1), instance.GasRemaining())

	// Successful Key Lookup
	module, err = interpreter.NewModule(pp, memoryMap)
	require.NoError(t, err)

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

	module.AddHostFunc("lookup", host_call.MakeLookupFunc(1, serviceState, memoryMap))

	_, instance, err = module.Run("test_lookup", initialGas, func(i polkavm.Instance) {
		err := i.SetMemory(memoryMap, ho, dataToHash)
		require.NoError(t, err)
	}, uint32(serviceId), ho, bo, 32)
	require.NoError(t, err)

	actualValue, err := instance.GetMemory(memoryMap, bo, len(val))
	require.NoError(t, err)

	assert.Equal(t, val, actualValue)
	assert.Equal(t, uint32(len(val)), instance.GetReg(polkavm.A0))
	assert.Equal(t, initialGas-host_call.LookupCost-int64(len(pp.Instructions)), instance.GasRemaining())
}

func TestRead(t *testing.T) {
	pp := &polkavm.Program{
		RODataSize: 0,
		RWDataSize: 256,
		StackSize:  512,
		Instructions: []polkavm.Instruction{
			{Opcode: polkavm.Ecalli, Imm: []uint32{0}, Offset: 0, Length: 1},
			{Opcode: polkavm.JumpIndirect, Imm: []uint32{0}, Reg: []polkavm.Reg{polkavm.RA}, Offset: 3, Length: 2},
		},
		Imports: []string{"read"},
		Exports: []polkavm.ProgramExport{{TargetCodeOffset: 0, Symbol: "test_read"}},
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

	serviceId := block.ServiceId(1)
	keyData := []byte("key_to_read")
	value := []byte("value_to_read")

	// Compute the hash H(E4(s) || keyData)
	serializer := serialization.NewSerializer(codec.NewJamCodec())
	serviceIdBytes, err := serializer.Encode(serviceId)
	require.NoError(t, err)

	hashInput := make([]byte, 0, len(serviceIdBytes)+len(keyData))
	hashInput = append(hashInput, serviceIdBytes...)
	hashInput = append(hashInput, keyData...)
	k := blake2b.Sum256(hashInput)

	serviceState := state.ServiceState{
		serviceId: state.ServiceAccount{
			Storage: map[crypto.Hash][]byte{
				k: value,
			},
		},
	}

	module.AddHostFunc("read", host_call.MakeReadFunc(1, serviceState, memoryMap))

	initialGas := int64(100)

	ko := memoryMap.RWDataAddress
	bo := memoryMap.RWDataAddress + 100
	kz := uint32(len(keyData))
	bz := uint32(32)

	result, instance, err := module.Run("test_read", initialGas, func(instance polkavm.Instance) {
		err = instance.SetMemory(memoryMap, ko, keyData)
		require.NoError(t, err)
	}, uint32(serviceId), ko, kz, bo, bz)
	require.NoError(t, err)

	actualValue, err := instance.GetMemory(memoryMap, bo, len(value))
	require.NoError(t, err)
	require.Equal(t, value, actualValue)

	require.Equal(t, uint32(len(value)), result)

	expectedGasRemaining := initialGas - host_call.ReadCost - int64(len(pp.Instructions))
	require.Equal(t, expectedGasRemaining, instance.GasRemaining())
}

func TestWrite(t *testing.T) {
	pp := &polkavm.Program{
		RODataSize: 0,
		RWDataSize: 256,
		StackSize:  512,
		Instructions: []polkavm.Instruction{
			{Opcode: polkavm.Ecalli, Imm: []uint32{0}, Offset: 0, Length: 1},
			{Opcode: polkavm.JumpIndirect, Imm: []uint32{0}, Reg: []polkavm.Reg{polkavm.RA}, Offset: 3, Length: 2},
		},
		Imports: []string{"write"},
		Exports: []polkavm.ProgramExport{{TargetCodeOffset: 0, Symbol: "test_write"}},
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

	serviceId := block.ServiceId(1)
	keyData := []byte("key_to_write")
	value := []byte("value_to_write")

	serializer := serialization.NewSerializer(codec.NewJamCodec())
	serviceIdBytes, err := serializer.Encode(serviceId)
	require.NoError(t, err)

	hashInput := append(serviceIdBytes, keyData...)
	k := blake2b.Sum256(hashInput)

	serviceState := state.ServiceState{
		serviceId: state.ServiceAccount{
			Storage: map[crypto.Hash][]byte{
				k: value,
			},
		},
	}

	module.AddHostFunc("write", host_call.MakeWriteFunc(serviceId, serviceState, memoryMap))

	initialGas := int64(100)

	ko := memoryMap.RWDataAddress
	vo := memoryMap.RWDataAddress + 100
	kz := uint32(len(keyData))
	vz := uint32(len(value))

	result, instance, err := module.Run("test_write", initialGas, func(instance polkavm.Instance) {
		err = instance.SetMemory(memoryMap, ko, keyData)
		require.NoError(t, err)

		err = instance.SetMemory(memoryMap, vo, value)
		require.NoError(t, err)
	}, ko, kz, vo, vz)
	require.NoError(t, err)

	actualValue, err := instance.GetMemory(memoryMap, vo, len(value))
	require.NoError(t, err)
	require.Equal(t, value, actualValue)

	require.Equal(t, uint32(len(value)), result)

	storedService, exists := serviceState[serviceId]
	require.True(t, exists)

	storedValue, keyExists := storedService.Storage[k]
	require.True(t, keyExists)
	require.Equal(t, value, storedValue)

	require.Equal(t, uint32(len(value)), result)

	expectedGasRemaining := initialGas - host_call.WriteCost - int64(len(pp.Instructions))
	require.Equal(t, expectedGasRemaining, instance.GasRemaining())
}
