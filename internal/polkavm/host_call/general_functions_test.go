package host_call_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/blake2b"

	"github.com/eigerco/strawberry/internal/block"
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/polkavm"
	"github.com/eigerco/strawberry/internal/polkavm/host_call"
	"github.com/eigerco/strawberry/internal/polkavm/interpreter"
	"github.com/eigerco/strawberry/internal/service"
	"github.com/eigerco/strawberry/pkg/serialization/codec/jam"
)

func TestGasRemaining(t *testing.T) {
	pp := &polkavm.Program{
		Instructions: []polkavm.Instruction{
			{Opcode: polkavm.Ecalli, Imm: []uint32{0}, Offset: 0, Length: 1},
			{Opcode: polkavm.JumpIndirect, Imm: []uint32{0}, Reg: []polkavm.Reg{polkavm.RA}, Offset: 1, Length: 2},
		},
	}

	memoryMap, err := polkavm.NewMemoryMap(polkavm.VmMaxPageSize, 0, 0, 4096, 0)
	require.NoError(t, err)

	mem := memoryMap.NewMemory(nil, nil, nil)

	initialRegs := polkavm.Registers{
		polkavm.RA: polkavm.VmAddressReturnToHost,
		polkavm.SP: memoryMap.StackAddressHigh,
	}
	initialGas := uint64(100)
	hostCall := func(hostCall uint32, gasCounter polkavm.Gas, regs polkavm.Registers, mem polkavm.Memory, x struct{}) (polkavm.Gas, polkavm.Registers, polkavm.Memory, struct{}, error) {
		gasCounter, regs, err = host_call.GasRemaining(gasCounter, regs)
		require.NoError(t, err)
		return gasCounter, regs, mem, struct{}{}, nil
	}

	gas, regs, _, _, err := interpreter.InvokeHostCall(pp, memoryMap, 0, initialGas, initialRegs, mem, hostCall, struct{}{})
	require.ErrorIs(t, err, polkavm.ErrHalt)

	expectedGas := polkavm.Gas(initialGas) - host_call.GasRemainingCost - polkavm.GasCosts[polkavm.Ecalli]

	assert.Equal(t, int64(expectedGas), (int64(regs[polkavm.A1])<<32)|int64(regs[polkavm.A0]))
	assert.Equal(t, expectedGas-polkavm.GasCosts[polkavm.JumpIndirect], gas)
}

func TestLookup(t *testing.T) {
	pp := &polkavm.Program{
		RODataSize: 0,
		RWDataSize: 256,
		StackSize:  512,
		Instructions: []polkavm.Instruction{
			{Opcode: polkavm.Ecalli, Imm: []uint32{0}, Offset: 0, Length: 1},
			{Opcode: polkavm.JumpIndirect, Imm: []uint32{0}, Reg: []polkavm.Reg{polkavm.RA}, Offset: 1, Length: 2},
		},
		Imports: []string{"lookup"},
		Exports: []polkavm.ProgramExport{{TargetCodeOffset: 0, Symbol: "test_lookup"}},
	}

	memoryMap, err := polkavm.NewMemoryMap(polkavm.VmMinPageSize, 0, 256, 512, 0)
	require.NoError(t, err)
	t.Run("service_not_found", func(t *testing.T) {
		initialRegs := polkavm.Registers{
			polkavm.RA: polkavm.VmAddressReturnToHost,
			polkavm.SP: memoryMap.StackAddressHigh,
		}
		mem := memoryMap.NewMemory(nil, nil, nil)
		initialGas := uint64(100)
		hostCall := func(hostCall uint32, gasCounter polkavm.Gas, regs polkavm.Registers, mem polkavm.Memory, x service.ServiceAccount) (polkavm.Gas, polkavm.Registers, polkavm.Memory, service.ServiceAccount, error) {
			gasCounter, regs, mem, err = host_call.Lookup(gasCounter, regs, mem, service.ServiceAccount{}, 1, make(service.ServiceState))
			require.NoError(t, err)
			return gasCounter, regs, mem, x, nil
		}
		gasRemaining, regs, _, _, err := interpreter.InvokeHostCall(pp, memoryMap, 0, initialGas, initialRegs, mem, hostCall, service.ServiceAccount{})
		require.ErrorIs(t, err, polkavm.ErrHalt)

		assert.Equal(t, uint32(host_call.NONE), regs[polkavm.A0])
		assert.Equal(t, polkavm.Gas(initialGas)-host_call.LookupCost-polkavm.GasCosts[polkavm.JumpIndirect]-polkavm.GasCosts[polkavm.Ecalli], gasRemaining)
	})

	t.Run("successful_key_lookup", func(t *testing.T) {
		mem := memoryMap.NewMemory(nil, nil, nil)
		initialGas := uint64(100)
		serviceId := block.ServiceId(1)
		val := []byte("value to store")
		ho := memoryMap.RWDataAddress
		bo := memoryMap.RWDataAddress + 100
		dataToHash := make([]byte, 32)
		copy(dataToHash, "hash")
		hash := blake2b.Sum256(dataToHash)
		err := mem.Write(ho, dataToHash)
		require.NoError(t, err)

		initialRegs := polkavm.Registers{
			polkavm.RA: polkavm.VmAddressReturnToHost,
			polkavm.SP: memoryMap.StackAddressHigh,
			polkavm.A0: uint32(serviceId),
			polkavm.A1: ho,
			polkavm.A2: bo,
			polkavm.A3: 32,
		}
		sa := service.ServiceAccount{
			Storage: map[crypto.Hash][]byte{
				hash: val,
			},
		}
		serviceState := service.ServiceState{
			serviceId: sa,
		}

		hostCall := func(hostCall uint32, gasCounter polkavm.Gas, regs polkavm.Registers, mem polkavm.Memory, x service.ServiceAccount) (polkavm.Gas, polkavm.Registers, polkavm.Memory, service.ServiceAccount, error) {
			gasCounter, regs, mem, err = host_call.Lookup(gasCounter, regs, mem, sa, serviceId, serviceState)
			require.NoError(t, err)
			return gasCounter, regs, mem, x, nil
		}
		gasRemaining, regs, mem, _, err := interpreter.InvokeHostCall(pp, memoryMap, 0, initialGas, initialRegs, mem, hostCall, sa)
		require.ErrorIs(t, err, polkavm.ErrHalt)

		actualValue := make([]byte, len(val))
		err = mem.Read(bo, actualValue)
		require.NoError(t, err)

		assert.Equal(t, val, actualValue)
		assert.Equal(t, uint32(len(val)), regs[polkavm.A0])
		assert.Equal(t, polkavm.Gas(initialGas)-host_call.LookupCost-polkavm.GasCosts[polkavm.Ecalli]-polkavm.GasCosts[polkavm.JumpIndirect], gasRemaining)
	})
}

func TestRead(t *testing.T) {
	pp := &polkavm.Program{
		Instructions: []polkavm.Instruction{
			{Opcode: polkavm.Ecalli, Imm: []uint32{0}, Offset: 0, Length: 1},
			{Opcode: polkavm.JumpIndirect, Imm: []uint32{0}, Reg: []polkavm.Reg{polkavm.RA}, Offset: 1, Length: 2},
		},
	}

	memoryMap, err := polkavm.NewMemoryMap(polkavm.VmMinPageSize, 0, 256, 512, 0)
	require.NoError(t, err)

	serviceId := block.ServiceId(1)
	keyData := []byte("key_to_read")
	value := []byte("value_to_read")

	// Compute the hash H(E4(s) || keyData)
	serviceIdBytes, err := jam.Marshal(serviceId)
	require.NoError(t, err)

	hashInput := make([]byte, 0, len(serviceIdBytes)+len(keyData))
	hashInput = append(hashInput, serviceIdBytes...)
	hashInput = append(hashInput, keyData...)
	k := blake2b.Sum256(hashInput)

	sa := service.ServiceAccount{
		Storage: map[crypto.Hash][]byte{
			k: value,
		},
	}
	serviceState := service.ServiceState{
		serviceId: sa,
	}

	initialGas := uint64(100)

	ko := memoryMap.RWDataAddress
	bo := memoryMap.RWDataAddress + 100
	kz := uint32(len(keyData))
	bz := uint32(32)
	initialRegs := polkavm.Registers{
		polkavm.RA: polkavm.VmAddressReturnToHost,
		polkavm.SP: memoryMap.StackAddressHigh,
		polkavm.A0: uint32(serviceId),
		polkavm.A1: ko,
		polkavm.A2: kz,
		polkavm.A3: bo,
		polkavm.A4: bz,
	}
	mem := memoryMap.NewMemory(nil, nil, nil)
	err = mem.Write(ko, keyData)
	require.NoError(t, err)

	hostCall := func(hostCall uint32, gasCounter polkavm.Gas, regs polkavm.Registers, mem polkavm.Memory, x service.ServiceAccount) (polkavm.Gas, polkavm.Registers, polkavm.Memory, service.ServiceAccount, error) {
		gasCounter, regs, mem, err = host_call.Read(gasCounter, regs, mem, x, serviceId, serviceState)
		require.NoError(t, err)
		return gasCounter, regs, mem, x, nil
	}
	gasRemaining, regs, mem, _, err := interpreter.InvokeHostCall(pp, memoryMap, 0, initialGas, initialRegs, mem, hostCall, sa)
	require.ErrorIs(t, err, polkavm.ErrHalt)

	actualValue := make([]byte, len(value))
	err = mem.Read(bo, actualValue)
	require.NoError(t, err)
	require.Equal(t, value, actualValue)

	require.Equal(t, uint32(len(value)), regs[polkavm.A0])

	expectedGasRemaining := polkavm.Gas(initialGas) - host_call.ReadCost - polkavm.GasCosts[polkavm.Ecalli] - polkavm.GasCosts[polkavm.JumpIndirect]
	require.Equal(t, expectedGasRemaining, gasRemaining)
}

func TestWrite(t *testing.T) {
	pp := &polkavm.Program{
		Instructions: []polkavm.Instruction{
			{Opcode: polkavm.Ecalli, Imm: []uint32{0}, Offset: 0, Length: 1},
			{Opcode: polkavm.JumpIndirect, Imm: []uint32{0}, Reg: []polkavm.Reg{polkavm.RA}, Offset: 1, Length: 2},
		},
	}

	memoryMap, err := polkavm.NewMemoryMap(polkavm.VmMinPageSize, 0, 256, 512, 0)
	require.NoError(t, err)

	serviceId := block.ServiceId(1)
	keyData := []byte("key_to_write")
	value := []byte("value_to_write")

	serviceIdBytes, err := jam.Marshal(serviceId)
	require.NoError(t, err)

	hashInput := append(serviceIdBytes, keyData...)
	k := blake2b.Sum256(hashInput)

	sa := service.ServiceAccount{
		Balance: 200,
		Storage: map[crypto.Hash][]byte{
			k: value,
		},
	}

	initialGas := uint64(100)

	ko := memoryMap.RWDataAddress
	kz := uint32(len(keyData))

	vo := memoryMap.RWDataAddress + 100
	vz := uint32(len(value))

	initialRegs := polkavm.Registers{
		polkavm.RA: polkavm.VmAddressReturnToHost,
		polkavm.SP: memoryMap.StackAddressHigh,
		polkavm.A0: ko,
		polkavm.A1: kz,
		polkavm.A2: vo,
		polkavm.A3: vz,
	}
	mem := memoryMap.NewMemory(nil, nil, nil)
	err = mem.Write(ko, keyData)
	require.NoError(t, err)
	err = mem.Write(vo, value)
	require.NoError(t, err)
	hostCall := func(hostCall uint32, gasCounter polkavm.Gas, regs polkavm.Registers, mem polkavm.Memory, a service.ServiceAccount) (polkavm.Gas, polkavm.Registers, polkavm.Memory, service.ServiceAccount, error) {
		gasCounter, regs, mem, _, err = host_call.Write(gasCounter, regs, mem, sa, serviceId)
		require.NoError(t, err)
		return gasCounter, regs, mem, a, nil
	}
	gasRemaining, regs, _, sa, err := interpreter.InvokeHostCall(pp, memoryMap, 0, initialGas, initialRegs, mem, hostCall, sa)
	require.ErrorIs(t, err, polkavm.ErrHalt)

	actualValue := make([]byte, len(value))
	err = mem.Read(vo, actualValue)
	require.NoError(t, err)
	require.Equal(t, value, actualValue)

	actualKey := make([]byte, len(keyData))
	err = mem.Read(ko, actualKey)
	require.NoError(t, err)
	require.Equal(t, keyData, actualKey)

	require.Equal(t, uint32(len(value)), regs[polkavm.A0])
	require.NotNil(t, sa)
	storedValue, keyExists := sa.Storage[k]
	require.True(t, keyExists)
	require.Equal(t, value, storedValue)

	expectedGasRemaining := polkavm.Gas(initialGas) - host_call.WriteCost - polkavm.GasCosts[polkavm.Ecalli] - polkavm.GasCosts[polkavm.JumpIndirect]
	require.Equal(t, expectedGasRemaining, gasRemaining)
}

func TestInfo(t *testing.T) {
	pp := &polkavm.Program{
		RODataSize: 0,
		RWDataSize: 256,
		StackSize:  512,
		Instructions: []polkavm.Instruction{
			{Opcode: polkavm.Ecalli, Imm: []uint32{0}, Offset: 0, Length: 1},
			{Opcode: polkavm.JumpIndirect, Imm: []uint32{0}, Reg: []polkavm.Reg{polkavm.RA}, Offset: 1, Length: 2},
		},
		Imports: []string{"info"},
		Exports: []polkavm.ProgramExport{{TargetCodeOffset: 0, Symbol: "test_info"}},
	}

	memoryMap, err := polkavm.NewMemoryMap(polkavm.VmMinPageSize, 0, 256, 512, 0)
	require.NoError(t, err)

	serviceId := block.ServiceId(1)

	sampleAccount := service.ServiceAccount{
		CodeHash:               crypto.Hash{0x01, 0x02, 0x03},
		Balance:                1000,
		GasLimitForAccumulator: 5000,
		GasLimitOnTransfer:     2000,
		Storage:                make(map[crypto.Hash][]byte),
		PreimageMeta:           make(map[service.PreImageMetaKey]service.PreimageHistoricalTimeslots),
	}

	sampleAccount.Storage[crypto.Hash{0xAA}] = []byte("value1")
	sampleAccount.Storage[crypto.Hash{0xBB}] = []byte("value2")

	serviceState := service.ServiceState{
		serviceId: sampleAccount,
	}

	initialGas := uint64(100)

	omega1 := memoryMap.RWDataAddress
	mem := memoryMap.NewMemory(nil, nil, nil)
	initialRegs := polkavm.Registers{
		polkavm.RA: polkavm.VmAddressReturnToHost,
		polkavm.SP: memoryMap.StackAddressHigh,
		polkavm.A0: uint32(serviceId),
		polkavm.A1: omega1,
	}
	hostCall := func(hostCall uint32, gasCounter polkavm.Gas, regs polkavm.Registers, mem polkavm.Memory, x service.ServiceAccount) (polkavm.Gas, polkavm.Registers, polkavm.Memory, service.ServiceAccount, error) {
		gasCounter, regs, mem, err = host_call.Info(gasCounter, regs, mem, serviceId, serviceState)
		require.NoError(t, err)
		return gasCounter, regs, mem, x, nil
	}
	gasRemaining, regs, _, _, err := interpreter.InvokeHostCall(pp, memoryMap, 0, initialGas, initialRegs, mem, hostCall, sampleAccount)
	require.ErrorIs(t, err, polkavm.ErrHalt)

	require.Equal(t, uint32(host_call.OK), regs[polkavm.A0])

	var accountInfo host_call.AccountInfo
	m, err := jam.Marshal(accountInfo)
	require.NoError(t, err)

	data := make([]byte, len(m))
	err = mem.Read(omega1, data)
	require.NoError(t, err)

	var receivedAccountInfo host_call.AccountInfo
	err = jam.Unmarshal(data, &receivedAccountInfo)
	require.NoError(t, err)

	expectedAccountInfo := host_call.AccountInfo{
		CodeHash:               crypto.Hash(sampleAccount.CodeHash[:]),
		Balance:                sampleAccount.Balance,
		ThresholdBalance:       sampleAccount.ThresholdBalance(),
		GasLimitForAccumulator: sampleAccount.GasLimitForAccumulator,
		GasLimitOnTransfer:     sampleAccount.GasLimitOnTransfer,
		TotalStorageSize:       sampleAccount.TotalStorageSize(),
		TotalItems:             sampleAccount.TotalItems(),
	}

	require.Equal(t, expectedAccountInfo, receivedAccountInfo)

	expectedGasRemaining := polkavm.Gas(initialGas) - host_call.InfoCost - polkavm.GasCosts[polkavm.Ecalli] - polkavm.GasCosts[polkavm.JumpIndirect]
	require.Equal(t, expectedGasRemaining, gasRemaining)
}
