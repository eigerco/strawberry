package host_call_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/eigerco/strawberry/internal/block"
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/jamtime"
	"github.com/eigerco/strawberry/internal/polkavm"
	"github.com/eigerco/strawberry/internal/polkavm/host_call"
	"github.com/eigerco/strawberry/internal/polkavm/interpreter"
	"github.com/eigerco/strawberry/internal/service"
)

func TestHistoricalLookup(t *testing.T) {
	pp := &polkavm.Program{
		Instructions: []polkavm.Instruction{
			{Opcode: polkavm.Ecalli, Imm: []uint32{0}, Offset: 0, Length: 1},
			{Opcode: polkavm.JumpIndirect, Imm: []uint32{0}, Reg: []polkavm.Reg{polkavm.RA}, Offset: 1, Length: 2},
		},
	}

	memoryMap, err := polkavm.NewMemoryMap(0, 256, 512, 0)
	require.NoError(t, err)

	serviceId := block.ServiceId(1)
	initialGas := uint64(100)
	timeslot := jamtime.Timeslot(9)

	preimage := []byte("historical_data")
	dataToHash := make([]byte, 32)
	copy(dataToHash, preimage)

	h := crypto.HashData(dataToHash)

	sa := service.ServiceAccount{
		PreimageLookup: map[crypto.Hash][]byte{
			h: preimage,
		},
		PreimageMeta: map[service.PreImageMetaKey]service.PreimageHistoricalTimeslots{
			{
				Hash:   h,
				Length: service.PreimageLength(len(preimage)),
			}: {0, 10},
		},
	}

	serviceState := service.ServiceState{
		serviceId: sa,
	}

	hashData := make([]byte, 32)
	copy(hashData, preimage)

	ho := memoryMap.RWDataAddress
	bo := memoryMap.RWDataAddress + 100
	bz := uint32(64)

	initialRegs := polkavm.Registers{
		polkavm.RA: polkavm.VmAddressReturnToHost,
		polkavm.SP: uint64(memoryMap.StackAddressHigh),
		polkavm.A0: uint64(serviceId),
		polkavm.A1: uint64(ho),
		polkavm.A2: uint64(bo),
		polkavm.A3: uint64(bz),
	}

	mem := memoryMap.NewMemory(nil, nil, nil)
	err = mem.Write(ho, hashData)
	require.NoError(t, err)

	ctxPair := polkavm.RefineContextPair{
		IntegratedPVMMap: make(map[uint64]polkavm.IntegratedPVM),
		Segments:         []polkavm.Segment{},
	}

	hostCall := func(hostCall uint32, gasCounter polkavm.Gas, regs polkavm.Registers, mem polkavm.Memory, x service.ServiceAccount) (polkavm.Gas, polkavm.Registers, polkavm.Memory, service.ServiceAccount, error) {
		gasCounterOut, regsOut, memOut, _, err := host_call.HistoricalLookup(
			gasCounter,
			regs,
			mem,
			ctxPair,
			serviceId,
			serviceState,
			timeslot,
		)
		require.NoError(t, err)
		return gasCounterOut, regsOut, memOut, x, err
	}

	gasRemaining, regsOut, memOut, _, err := interpreter.InvokeHostCall(pp, memoryMap, 0, initialGas, initialRegs, mem, hostCall, sa)
	require.ErrorIs(t, err, polkavm.ErrHalt)

	actualValue := make([]byte, len(preimage))
	err = memOut.Read(bo, actualValue)
	require.NoError(t, err)

	assert.Equal(t, preimage, actualValue)
	assert.Equal(t, uint64(len(preimage)), regsOut[polkavm.A0])

	expectedGasRemaining := polkavm.Gas(initialGas) - host_call.HistoricalLookupCost - polkavm.GasCosts[polkavm.Ecalli] - polkavm.GasCosts[polkavm.JumpIndirect]
	assert.Equal(t, expectedGasRemaining, gasRemaining)
}
