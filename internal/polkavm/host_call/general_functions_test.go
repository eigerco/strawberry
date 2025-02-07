package host_call_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/eigerco/strawberry/internal/block"
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/polkavm"
	"github.com/eigerco/strawberry/internal/polkavm/host_call"
	"github.com/eigerco/strawberry/internal/service"
	"github.com/eigerco/strawberry/pkg/serialization/codec/jam"
)

func TestGasRemaining(t *testing.T) {
	pp := &polkavm.Program{
		ProgramMemorySizes: polkavm.ProgramMemorySizes{
			InitialHeapPages: 100,
		},
	}

	_, initialRegs, err := polkavm.InitializeStandardProgram(pp, nil)
	require.NoError(t, err)

	gasRemaining, regs, err := host_call.GasRemaining(initialGas, initialRegs)
	require.NoError(t, err)

	assert.Equal(t, uint64(90), regs[polkavm.A0])
	assert.Equal(t, polkavm.Gas(90), gasRemaining)
}

func TestLookup(t *testing.T) {
	pp := &polkavm.Program{
		ProgramMemorySizes: polkavm.ProgramMemorySizes{
			RODataSize:       0,
			RWDataSize:       256,
			StackSize:        512,
			InitialHeapPages: 100,
		},
	}

	t.Run("service_not_found", func(t *testing.T) {
		mem, initialRegs, err := polkavm.InitializeStandardProgram(pp, nil)
		require.NoError(t, err)
		gasRemaining, regs, _, err := host_call.Lookup(initialGas, initialRegs, mem, service.ServiceAccount{}, 1, make(service.ServiceState))
		require.NoError(t, err)
		assert.Equal(t, uint64(host_call.NONE), regs[polkavm.A0])
		assert.Equal(t, polkavm.Gas(90), gasRemaining)
	})

	t.Run("successful_key_lookup", func(t *testing.T) {
		serviceId := block.ServiceId(1)
		val := []byte("value to store")
		mem, initialRegs, err := polkavm.InitializeStandardProgram(pp, nil)
		require.NoError(t, err)
		ho := polkavm.RWAddressBase
		bo := polkavm.RWAddressBase + 100
		dataToHash := make([]byte, 32)
		copy(dataToHash, "hash")
		hash := crypto.HashData(dataToHash)
		err = mem.Write(ho, dataToHash)
		require.NoError(t, err)

		initialRegs[polkavm.A0] = uint64(serviceId)
		initialRegs[polkavm.A1] = uint64(ho)
		initialRegs[polkavm.A2] = uint64(bo)
		initialRegs[polkavm.A3] = 32
		sa := service.ServiceAccount{
			Storage: map[crypto.Hash][]byte{
				hash: val,
			},
		}
		serviceState := service.ServiceState{
			serviceId: sa,
		}

		gasRemaining, regs, mem, err := host_call.Lookup(initialGas, initialRegs, mem, sa, serviceId, serviceState)
		require.NoError(t, err)

		actualValue := make([]byte, len(val))
		err = mem.Read(bo, actualValue)
		require.NoError(t, err)

		assert.Equal(t, val, actualValue)
		assert.Equal(t, uint64(len(val)), regs[polkavm.A0])
		assert.Equal(t, polkavm.Gas(90), gasRemaining)
	})
}

func TestRead(t *testing.T) {
	pp := &polkavm.Program{
		ProgramMemorySizes: polkavm.ProgramMemorySizes{
			RWDataSize:       256,
			StackSize:        512,
			InitialHeapPages: 10,
		},
	}

	mem, initialRegs, err := polkavm.InitializeStandardProgram(pp, nil)
	require.NoError(t, err)

	serviceId := block.ServiceId(1)
	keyData := []byte("key_to_read")
	value := []byte("value_to_read")

	// Compute the hash H(E4(s) || keyData)
	serviceIdBytes, err := jam.Marshal(uint64(serviceId))
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
	bz := uint32(32)
	initialRegs[polkavm.A0] = uint64(serviceId)
	initialRegs[polkavm.A1] = uint64(ko)
	initialRegs[polkavm.A2] = uint64(kz)
	initialRegs[polkavm.A3] = uint64(bo)
	initialRegs[polkavm.A4] = uint64(bz)
	err = mem.Write(ko, keyData)
	require.NoError(t, err)

	gasRemaining, regs, mem, err := host_call.Read(initialGas, initialRegs, mem, sa, serviceId, serviceState)
	require.NoError(t, err)
	actualValue := make([]byte, len(value))
	err = mem.Read(bo, actualValue)
	require.NoError(t, err)

	assert.Equal(t, value, actualValue)
	assert.Equal(t, uint64(len(value)), regs[polkavm.A0])

	assert.Equal(t, polkavm.Gas(90), gasRemaining)
}

func TestWrite(t *testing.T) {
	pp := &polkavm.Program{
		ProgramMemorySizes: polkavm.ProgramMemorySizes{
			RWDataSize:       256,
			StackSize:        512,
			InitialHeapPages: 10,
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

	gasRemaining, regs, mem, _, err := host_call.Write(initialGas, initialRegs, mem, sa, serviceId)
	require.NoError(t, err)

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

	require.Equal(t, polkavm.Gas(90), gasRemaining)
}

func TestInfo(t *testing.T) {
	pp := &polkavm.Program{
		ProgramMemorySizes: polkavm.ProgramMemorySizes{
			RWDataSize:       256,
			StackSize:        512,
			InitialHeapPages: 10,
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

	omega1 := polkavm.RWAddressBase
	initialRegs[polkavm.A0] = uint64(serviceId)
	initialRegs[polkavm.A1] = uint64(omega1)

	gasRemaining, regs, mem, err := host_call.Info(initialGas, initialRegs, mem, serviceId, serviceState)
	require.NoError(t, err)

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

	require.Equal(t, polkavm.Gas(90), gasRemaining)
}
