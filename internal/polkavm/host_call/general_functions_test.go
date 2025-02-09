package host_call_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

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
		ProgramMemorySizes: polkavm.ProgramMemorySizes{
			InitialHeapPages: 100,
		},
		CodeAndJumpTable: polkavm.CodeAndJumpTable{
			Instructions: []polkavm.Instruction{
				{Opcode: polkavm.Ecalli, Imm: []uint32{0}, Offset: 0, Length: 1},
				{Opcode: polkavm.JumpIndirect, Imm: []uint32{0}, Reg: []polkavm.Reg{polkavm.RA}, Offset: 1, Length: 2},
			},
		},
	}

	mem, initialRegs, err := polkavm.InitializeStandardProgram(pp, nil)
	require.NoError(t, err)

	initialGas := uint64(100)
	hostCall := func(hostCall uint32, gasCounter polkavm.Gas, regs polkavm.Registers, mem polkavm.Memory, x struct{}) (polkavm.Gas, polkavm.Registers, polkavm.Memory, struct{}, error) {
		gasCounter, regs, err = host_call.GasRemaining(gasCounter, regs)
		require.NoError(t, err)
		return gasCounter, regs, mem, struct{}{}, nil
	}

	gas, regs, _, _, err := interpreter.InvokeHostCall(pp, 0, initialGas, initialRegs, mem, hostCall, struct{}{})
	require.ErrorIs(t, err, polkavm.ErrHalt)

	expectedGas := polkavm.Gas(initialGas) - host_call.GasRemainingCost - polkavm.GasCosts[polkavm.Ecalli]

	assert.Equal(t, int64(expectedGas), (int64(regs[polkavm.A1])<<32)|int64(regs[polkavm.A0]))
	assert.Equal(t, expectedGas-polkavm.GasCosts[polkavm.JumpIndirect], gas)
}

func TestLookup(t *testing.T) {
	pp := &polkavm.Program{
		ProgramMemorySizes: polkavm.ProgramMemorySizes{
			RODataSize:       0,
			RWDataSize:       256,
			StackSize:        512,
			InitialHeapPages: 100,
		},
		CodeAndJumpTable: polkavm.CodeAndJumpTable{
			Instructions: []polkavm.Instruction{
				{Opcode: polkavm.Ecalli, Imm: []uint32{0}, Offset: 0, Length: 1},
				{Opcode: polkavm.JumpIndirect, Imm: []uint32{0}, Reg: []polkavm.Reg{polkavm.RA}, Offset: 1, Length: 2},
			},
		},
	}

	t.Run("service_not_found", func(t *testing.T) {
		mem, initialRegs, err := polkavm.InitializeStandardProgram(pp, nil)
		require.NoError(t, err)
		initialGas := uint64(100)
		hostCall := func(hostCall uint32, gasCounter polkavm.Gas, regs polkavm.Registers, mem polkavm.Memory, x service.ServiceAccount) (polkavm.Gas, polkavm.Registers, polkavm.Memory, service.ServiceAccount, error) {
			gasCounter, regs, mem, err = host_call.Lookup(gasCounter, regs, mem, service.ServiceAccount{}, 1, make(service.ServiceState))
			require.NoError(t, err)
			return gasCounter, regs, mem, x, nil
		}
		gasRemaining, regs, _, _, err := interpreter.InvokeHostCall(pp, 0, initialGas, initialRegs, mem, hostCall, service.ServiceAccount{})
		require.ErrorIs(t, err, polkavm.ErrHalt)

		assert.Equal(t, uint64(host_call.NONE), regs[polkavm.A0])
		assert.Equal(t, polkavm.Gas(initialGas)-host_call.LookupCost-polkavm.GasCosts[polkavm.JumpIndirect]-polkavm.GasCosts[polkavm.Ecalli], gasRemaining)
	})

	t.Run("successful_key_lookup", func(t *testing.T) {
		initialGas := uint64(100)
		serviceId := block.ServiceId(1)
		val := []byte("value to store")
		mem, initialRegs, err := polkavm.InitializeStandardProgram(pp, nil)
		require.NoError(t, err)
		ho := polkavm.RWAddressBase
		bo := polkavm.RWAddressBase + 100
		dataToHash := make([]byte, 32)
		copy(dataToHash, "hash")

		err = mem.Write(ho, dataToHash)
		require.NoError(t, err)

		initialRegs[polkavm.A0] = uint64(serviceId)
		initialRegs[polkavm.A1] = uint64(ho)       // h
		initialRegs[polkavm.A2] = uint64(bo)       // o
		initialRegs[polkavm.A3] = 0                // f
		initialRegs[polkavm.A4] = uint64(len(val)) // l
		sa := service.ServiceAccount{
			PreimageLookup: map[crypto.Hash][]byte{
				crypto.Hash(dataToHash): val,
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
		gasRemaining, regs, mem, _, err := interpreter.InvokeHostCall(pp, 0, initialGas, initialRegs, mem, hostCall, sa)
		require.ErrorIs(t, err, polkavm.ErrHalt)

		actualValue := make([]byte, len(val))
		err = mem.Read(bo, actualValue)
		require.NoError(t, err)

		assert.Equal(t, val, actualValue)
		assert.Equal(t, uint64(len(val)), regs[polkavm.A0])
		assert.Equal(t, polkavm.Gas(initialGas)-host_call.LookupCost-polkavm.GasCosts[polkavm.Ecalli]-polkavm.GasCosts[polkavm.JumpIndirect], gasRemaining)
	})
}

func TestRead(t *testing.T) {
	pp := &polkavm.Program{
		ProgramMemorySizes: polkavm.ProgramMemorySizes{
			RWDataSize:       256,
			StackSize:        512,
			InitialHeapPages: 10,
		},
		CodeAndJumpTable: polkavm.CodeAndJumpTable{
			Instructions: []polkavm.Instruction{
				{Opcode: polkavm.Ecalli, Imm: []uint32{0}, Offset: 0, Length: 1},
				{Opcode: polkavm.JumpIndirect, Imm: []uint32{0}, Reg: []polkavm.Reg{polkavm.RA}, Offset: 1, Length: 2},
			},
		},
	}

	mem, initialRegs, err := polkavm.InitializeStandardProgram(pp, nil)
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
	k := crypto.HashData(hashInput)

	sa := service.ServiceAccount{
		Storage: map[crypto.Hash][]byte{
			k: value,
		},
	}
	serviceState := service.ServiceState{
		serviceId: sa,
	}

	ko := polkavm.RWAddressBase
	bo := polkavm.RWAddressBase + 100
	kz := uint32(len(keyData))
	vLen := uint64(len(value))

	initialRegs[polkavm.A0] = uint64(serviceId)
	initialRegs[polkavm.A1] = uint64(ko)
	initialRegs[polkavm.A2] = uint64(kz)
	initialRegs[polkavm.A3] = uint64(bo)
	initialRegs[polkavm.A4] = 0    // f = offset (starting at 0)
	initialRegs[polkavm.A5] = vLen // l = length (32 bytes)

	err = mem.Write(ko, keyData)
	require.NoError(t, err)

	hostCall := func(hostCall uint32, gasCounter polkavm.Gas, regs polkavm.Registers, mem polkavm.Memory, x service.ServiceAccount) (polkavm.Gas, polkavm.Registers, polkavm.Memory, service.ServiceAccount, error) {
		gasCounter, regs, mem, err = host_call.Read(gasCounter, regs, mem, x, serviceId, serviceState)
		require.NoError(t, err)
		return gasCounter, regs, mem, x, nil
	}
	gasRemaining, regs, mem, _, err := interpreter.InvokeHostCall(pp, 0, initialGas, initialRegs, mem, hostCall, sa)
	require.ErrorIs(t, err, polkavm.ErrHalt)

	actualValue := make([]byte, len(value))
	err = mem.Read(bo, actualValue)
	require.NoError(t, err)

	assert.Equal(t, value, actualValue)
	assert.Equal(t, uint64(len(value)), regs[polkavm.A0])

	expectedGasRemaining := polkavm.Gas(initialGas) - host_call.ReadCost - polkavm.GasCosts[polkavm.Ecalli] - polkavm.GasCosts[polkavm.JumpIndirect]
	assert.Equal(t, expectedGasRemaining, gasRemaining)
}

func TestWrite(t *testing.T) {
	pp := &polkavm.Program{
		ProgramMemorySizes: polkavm.ProgramMemorySizes{
			RWDataSize:       256,
			StackSize:        512,
			InitialHeapPages: 10,
		},
		CodeAndJumpTable: polkavm.CodeAndJumpTable{
			Instructions: []polkavm.Instruction{
				{Opcode: polkavm.Ecalli, Imm: []uint32{0}, Offset: 0, Length: 1},
				{Opcode: polkavm.JumpIndirect, Imm: []uint32{0}, Reg: []polkavm.Reg{polkavm.RA}, Offset: 1, Length: 2},
			},
		},
	}

	mem, initialRegs, err := polkavm.InitializeStandardProgram(pp, nil)
	require.NoError(t, err)

	serviceId := block.ServiceId(1)
	keyData := []byte("key_to_write")
	value := []byte("value_to_write")

	serviceIdBytes, err := jam.Marshal(serviceId)
	require.NoError(t, err)

	hashInput := append(serviceIdBytes, keyData...)
	k := crypto.HashData(hashInput)

	sa := service.ServiceAccount{
		Balance: 200,
		Storage: map[crypto.Hash][]byte{
			k: value,
		},
	}

	initialGas := uint64(100)

	ko := polkavm.RWAddressBase
	kz := uint32(len(keyData))

	vo := polkavm.RWAddressBase + 100
	vz := uint32(len(value))

	initialRegs[polkavm.A0] = uint64(ko)
	initialRegs[polkavm.A1] = uint64(kz)
	initialRegs[polkavm.A2] = uint64(vo)
	initialRegs[polkavm.A3] = uint64(vz)
	err = mem.Write(ko, keyData)
	require.NoError(t, err)
	err = mem.Write(vo, value)
	require.NoError(t, err)
	hostCall := func(hostCall uint32, gasCounter polkavm.Gas, regs polkavm.Registers, mem polkavm.Memory, a service.ServiceAccount) (polkavm.Gas, polkavm.Registers, polkavm.Memory, service.ServiceAccount, error) {
		gasCounter, regs, mem, _, err = host_call.Write(gasCounter, regs, mem, sa, serviceId)
		require.NoError(t, err)
		return gasCounter, regs, mem, a, nil
	}
	gasRemaining, regs, _, sa, err := interpreter.InvokeHostCall(pp, 0, initialGas, initialRegs, mem, hostCall, sa)
	require.ErrorIs(t, err, polkavm.ErrHalt)

	actualValue := make([]byte, len(value))
	err = mem.Read(vo, actualValue)
	require.NoError(t, err)
	require.Equal(t, value, actualValue)

	actualKey := make([]byte, len(keyData))
	err = mem.Read(ko, actualKey)
	require.NoError(t, err)
	require.Equal(t, keyData, actualKey)

	require.Equal(t, uint64(len(value)), regs[polkavm.A0])
	require.NotNil(t, sa)
	storedValue, keyExists := sa.Storage[k]
	require.True(t, keyExists)
	require.Equal(t, value, storedValue)

	expectedGasRemaining := polkavm.Gas(initialGas) - host_call.WriteCost - polkavm.GasCosts[polkavm.Ecalli] - polkavm.GasCosts[polkavm.JumpIndirect]
	require.Equal(t, expectedGasRemaining, gasRemaining)
}

func TestInfo(t *testing.T) {
	pp := &polkavm.Program{
		ProgramMemorySizes: polkavm.ProgramMemorySizes{
			RWDataSize:       256,
			StackSize:        512,
			InitialHeapPages: 10,
		},
		CodeAndJumpTable: polkavm.CodeAndJumpTable{
			Instructions: []polkavm.Instruction{
				{Opcode: polkavm.Ecalli, Imm: []uint32{0}, Offset: 0, Length: 1},
				{Opcode: polkavm.JumpIndirect, Imm: []uint32{0}, Reg: []polkavm.Reg{polkavm.RA}, Offset: 1, Length: 2},
			},
		},
	}

	mem, initialRegs, err := polkavm.InitializeStandardProgram(pp, nil)
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

	omega1 := polkavm.RWAddressBase
	initialRegs[polkavm.A0] = uint64(serviceId)
	initialRegs[polkavm.A1] = uint64(omega1)
	hostCall := func(hostCall uint32, gasCounter polkavm.Gas, regs polkavm.Registers, mem polkavm.Memory, x service.ServiceAccount) (polkavm.Gas, polkavm.Registers, polkavm.Memory, service.ServiceAccount, error) {
		gasCounter, regs, mem, err = host_call.Info(gasCounter, regs, mem, serviceId, serviceState)
		require.NoError(t, err)
		return gasCounter, regs, mem, x, nil
	}
	gasRemaining, regs, _, _, err := interpreter.InvokeHostCall(pp, 0, initialGas, initialRegs, mem, hostCall, sampleAccount)
	require.ErrorIs(t, err, polkavm.ErrHalt)

	require.Equal(t, uint64(host_call.OK), regs[polkavm.A0])

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
