package host_call_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/eigerco/strawberry/internal/block"
	"github.com/eigerco/strawberry/internal/common"
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/jamtime"
	"github.com/eigerco/strawberry/internal/polkavm"
	"github.com/eigerco/strawberry/internal/polkavm/host_call"
	"github.com/eigerco/strawberry/internal/polkavm/interpreter"
	"github.com/eigerco/strawberry/internal/service"
)

var initialGas = uint64(100)

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

func TestImport(t *testing.T) {
	pp := &polkavm.Program{
		Instructions: []polkavm.Instruction{
			{Opcode: polkavm.Ecalli, Imm: []uint32{0}, Offset: 0, Length: 1},
			{Opcode: polkavm.JumpIndirect, Imm: []uint32{0}, Reg: []polkavm.Reg{polkavm.RA}, Offset: 1, Length: 2},
		},
	}

	memoryMap, err := polkavm.NewMemoryMap(0, 256, 512, 0)
	require.NoError(t, err)

	segmentData := [common.SizeOfSegment]byte{}
	for i := range segmentData {
		segmentData[i] = byte('A')
	}
	importedSegments := []polkavm.Segment{segmentData}

	bo := memoryMap.RWDataAddress + 100
	bz := uint32(50)

	initialRegs := polkavm.Registers{
		polkavm.RA: polkavm.VmAddressReturnToHost,
		polkavm.SP: uint64(memoryMap.StackAddressHigh),
		polkavm.A0: uint64(0),
		polkavm.A1: uint64(bo),
		polkavm.A2: uint64(bz),
	}

	mem := memoryMap.NewMemory(nil, nil, nil)

	hostCall := func(hostCall uint32, gasCounter polkavm.Gas, regs polkavm.Registers, mem polkavm.Memory, x service.ServiceAccount) (polkavm.Gas, polkavm.Registers, polkavm.Memory, service.ServiceAccount, error) {
		gasCounterOut, regsOut, memOut, _, err := host_call.Import(
			gasCounter,
			regs,
			mem,
			polkavm.RefineContextPair{},
			importedSegments,
		)
		require.NoError(t, err)
		return gasCounterOut, regsOut, memOut, x, err
	}

	gasRemaining, regsOut, memOut, _, err := interpreter.InvokeHostCall(pp, memoryMap, 0, initialGas, initialRegs, mem, hostCall, service.ServiceAccount{})
	require.ErrorIs(t, err, polkavm.ErrHalt)

	actualValue := make([]byte, bz)
	err = memOut.Read(bo, actualValue)
	require.NoError(t, err)

	expectedData := make([]byte, bz)
	for i := range expectedData {
		expectedData[i] = 'A'
	}

	assert.Equal(t, expectedData, actualValue)
	assert.Equal(t, uint64(host_call.OK), regsOut[polkavm.A0])

	expectedGasRemaining := polkavm.Gas(initialGas) - host_call.ImportCost - polkavm.GasCosts[polkavm.Ecalli] - polkavm.GasCosts[polkavm.JumpIndirect]
	assert.Equal(t, expectedGasRemaining, gasRemaining)
}

func TestExport(t *testing.T) {
	pp := &polkavm.Program{
		Instructions: []polkavm.Instruction{
			{Opcode: polkavm.Ecalli, Imm: []uint32{0}, Offset: 0, Length: 1},
			{Opcode: polkavm.JumpIndirect, Imm: []uint32{0}, Reg: []polkavm.Reg{polkavm.RA}, Offset: 1, Length: 2},
		},
	}

	memoryMap, err := polkavm.NewMemoryMap(0, 256, 512, 0)
	require.NoError(t, err)

	dataToExport := []byte("export_data")
	p := memoryMap.RWDataAddress

	mem := memoryMap.NewMemory(nil, nil, nil)
	err = mem.Write(p, dataToExport)
	require.NoError(t, err)

	exportOffset := uint64(10)

	initialRegs := polkavm.Registers{
		polkavm.RA: polkavm.VmAddressReturnToHost,
		polkavm.SP: uint64(memoryMap.StackAddressHigh),
		polkavm.A0: uint64(p),
		polkavm.A1: uint64(len(dataToExport)),
	}

	ctxPair := polkavm.RefineContextPair{
		Segments: []polkavm.Segment{},
	}

	hostCall := func(hostCall uint32, gasCounter polkavm.Gas, regs polkavm.Registers, mem polkavm.Memory, x service.ServiceAccount) (polkavm.Gas, polkavm.Registers, polkavm.Memory, service.ServiceAccount, error) {
		gasCounterOut, regsOut, memOut, ctxOut, err := host_call.Export(
			gasCounter,
			regs,
			mem,
			ctxPair,
			exportOffset,
		)
		require.NoError(t, err)

		ctxPair = ctxOut
		return gasCounterOut, regsOut, memOut, x, err
	}

	gasRemaining, regsOut, _, _, err := interpreter.InvokeHostCall(pp, memoryMap, 0, initialGas, initialRegs, mem, hostCall, service.ServiceAccount{})
	require.ErrorIs(t, err, polkavm.ErrHalt)

	// We expect ω7 = ς + |e| = 10 + 1 = 11
	assert.Equal(t, exportOffset+1, regsOut[polkavm.A0])

	require.Len(t, ctxPair.Segments, 1)
	seg := ctxPair.Segments[0]
	expectedSegment := make([]byte, common.SizeOfSegment)
	copy(expectedSegment, dataToExport)
	assert.Equal(t, expectedSegment, seg[:])

	expectedGasRemaining := polkavm.Gas(initialGas) - host_call.ExportCost - polkavm.GasCosts[polkavm.Ecalli] - polkavm.GasCosts[polkavm.JumpIndirect]
	assert.Equal(t, expectedGasRemaining, gasRemaining)
}

func TestMachine(t *testing.T) {
	pp := &polkavm.Program{
		Instructions: []polkavm.Instruction{
			{Opcode: polkavm.Ecalli, Imm: []uint32{0}, Offset: 0, Length: 1},
			{Opcode: polkavm.JumpIndirect, Imm: []uint32{0}, Reg: []polkavm.Reg{polkavm.RA}, Offset: 1, Length: 2},
		},
	}

	memoryMap, err := polkavm.NewMemoryMap(0, 256, 512, 0)
	require.NoError(t, err)

	dataToMachine := []byte("machine_code")
	po := memoryMap.RWDataAddress
	pz := len(dataToMachine)
	i := uint64(42)

	mem := memoryMap.NewMemory(nil, nil, nil)
	err = mem.Write(po, dataToMachine)
	require.NoError(t, err)

	initialRegs := polkavm.Registers{
		polkavm.RA: polkavm.VmAddressReturnToHost,
		polkavm.SP: uint64(memoryMap.StackAddressHigh),
		polkavm.A0: uint64(po),
		polkavm.A1: uint64(pz),
		polkavm.A2: i,
	}

	ctxPair := polkavm.RefineContextPair{
		IntegratedPVMMap: make(map[uint64]polkavm.IntegratedPVM),
		Segments:         []polkavm.Segment{},
	}

	hostCall := func(hostCall uint32, gasCounter polkavm.Gas, regs polkavm.Registers, mem polkavm.Memory, x service.ServiceAccount) (polkavm.Gas, polkavm.Registers, polkavm.Memory, service.ServiceAccount, error) {
		gasCounterOut, regsOut, memOut, ctxOut, err := host_call.Machine(
			gasCounter,
			regs,
			mem,
			ctxPair,
		)
		require.NoError(t, err)
		ctxPair = ctxOut
		return gasCounterOut, regsOut, memOut, x, err
	}

	gasRemaining, regsOut, _, _, err := interpreter.InvokeHostCall(pp, memoryMap, 0, initialGas, initialRegs, mem, hostCall, service.ServiceAccount{})
	require.ErrorIs(t, err, polkavm.ErrHalt)

	assert.Equal(t, uint64(0), regsOut[polkavm.A0])

	require.Len(t, ctxPair.IntegratedPVMMap, 1)
	vm, exists := ctxPair.IntegratedPVMMap[0]
	require.True(t, exists)

	assert.Equal(t, dataToMachine, vm.Code)
	assert.Equal(t, uint32(i), vm.InstructionCounter)

	expectedGasRemaining := polkavm.Gas(initialGas) - host_call.MachineCost - polkavm.GasCosts[polkavm.Ecalli] - polkavm.GasCosts[polkavm.JumpIndirect]
	assert.Equal(t, expectedGasRemaining, gasRemaining)
}
