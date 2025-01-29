package host_call_test

import (
	"math"
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
	"github.com/eigerco/strawberry/pkg/serialization/codec/jam"
)

var initialGas = uint64(100)

func TestHistoricalLookup(t *testing.T) {
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

	ho := polkavm.RWAddressBase
	bo := polkavm.RWAddressBase + 100
	bz := uint32(64)

	initialRegs[polkavm.A0] = uint64(serviceId)
	initialRegs[polkavm.A1] = uint64(ho)
	initialRegs[polkavm.A2] = uint64(bo)
	initialRegs[polkavm.A3] = uint64(bz)

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

	gasRemaining, regsOut, memOut, _, err := interpreter.InvokeHostCall(pp, 0, initialGas, initialRegs, mem, hostCall, sa)
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

	segmentData := [common.SizeOfSegment]byte{}
	for i := range segmentData {
		segmentData[i] = byte('A')
	}
	importedSegments := []polkavm.Segment{segmentData}

	bo := polkavm.RWAddressBase + 100
	bz := uint32(50)

	initialRegs[polkavm.A0] = uint64(0)
	initialRegs[polkavm.A1] = uint64(bo)
	initialRegs[polkavm.A2] = uint64(bz)

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

	gasRemaining, regsOut, memOut, _, err := interpreter.InvokeHostCall(pp, 0, initialGas, initialRegs, mem, hostCall, service.ServiceAccount{})
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

	dataToExport := []byte("export_data")
	p := polkavm.RWAddressBase

	err = mem.Write(p, dataToExport)
	require.NoError(t, err)

	exportOffset := uint64(10)

	initialRegs[polkavm.A0] = uint64(p)
	initialRegs[polkavm.A1] = uint64(len(dataToExport))

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

	gasRemaining, regsOut, _, _, err := interpreter.InvokeHostCall(pp, 0, initialGas, initialRegs, mem, hostCall, service.ServiceAccount{})
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

	dataToMachine := []byte("machine_code")
	po := polkavm.RWAddressBase
	pz := len(dataToMachine)
	i := uint64(42)

	err = mem.Write(po, dataToMachine)
	require.NoError(t, err)

	initialRegs[polkavm.A0] = uint64(po)
	initialRegs[polkavm.A1] = uint64(pz)
	initialRegs[polkavm.A2] = i

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

	gasRemaining, regsOut, _, _, err := interpreter.InvokeHostCall(pp, 0, initialGas, initialRegs, mem, hostCall, service.ServiceAccount{})
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

func TestPeek(t *testing.T) {
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

	n := uint64(0)
	o := polkavm.RWAddressBase + 100
	z := uint64(1)

	uData := []byte("data_for_peek")

	uDataBase := polkavm.RWAddressBase
	require.True(t, uDataBase+uint32(len(uData)) < math.MaxUint32)

	err = mem.Write(uDataBase, uData)
	require.NoError(t, err)

	s := uint64(uDataBase) + 10

	u := polkavm.IntegratedPVM{
		Code:               nil,
		Ram:                mem,
		InstructionCounter: 0,
	}

	ctxPair := polkavm.RefineContextPair{
		IntegratedPVMMap: map[uint64]polkavm.IntegratedPVM{
			n: u,
		},
		Segments: []polkavm.Segment{},
	}

	initialRegs[polkavm.A0] = n
	initialRegs[polkavm.A1] = uint64(o)
	initialRegs[polkavm.A2] = s
	initialRegs[polkavm.A3] = z

	hostCall := func(hc uint32, gasCounter polkavm.Gas, regs polkavm.Registers, mm polkavm.Memory, x service.ServiceAccount) (polkavm.Gas, polkavm.Registers, polkavm.Memory, service.ServiceAccount, error) {
		gasCounterOut, regsOut, memOut, ctxOut, err := host_call.Peek(
			gasCounter,
			regs,
			mm,
			ctxPair,
		)
		require.NoError(t, err)
		ctxPair = ctxOut
		return gasCounterOut, regsOut, memOut, x, err
	}

	gasRemaining, regsOut, memOut, _, err := interpreter.InvokeHostCall(pp, 0, initialGas, initialRegs, mem, hostCall, service.ServiceAccount{})
	require.ErrorIs(t, err, polkavm.ErrHalt)

	assert.Equal(t, uint64(host_call.OK), regsOut[polkavm.A0])

	actualValue := make([]byte, z)
	err = memOut.Read(o, actualValue)
	require.NoError(t, err)

	startOffset := s - uint64(uDataBase)
	endOffset := startOffset + z
	expectedValue := uData[startOffset:endOffset]
	assert.Equal(t, expectedValue, actualValue)

	expectedGasRemaining := polkavm.Gas(initialGas) - host_call.PeekCost - polkavm.GasCosts[polkavm.Ecalli] - polkavm.GasCosts[polkavm.JumpIndirect]
	assert.Equal(t, expectedGasRemaining, gasRemaining)
}

func TestPoke(t *testing.T) {
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

	n := uint64(0)
	s := uint64(polkavm.RWAddressBase) + 100
	o := uint64(polkavm.RWAddressBase) + 200
	z := uint64(4)

	sourceData := []byte("data_for_poke")

	err = mem.Write(uint32(s), sourceData)
	require.NoError(t, err)

	u := polkavm.IntegratedPVM{
		Code:               nil,
		Ram:                mem,
		InstructionCounter: 0,
	}

	ctxPair := polkavm.RefineContextPair{
		IntegratedPVMMap: map[uint64]polkavm.IntegratedPVM{
			n: u,
		},
		Segments: []polkavm.Segment{},
	}

	initialRegs[polkavm.A0] = n
	initialRegs[polkavm.A1] = s
	initialRegs[polkavm.A2] = o
	initialRegs[polkavm.A3] = z

	hostCall := func(hc uint32, gasCounter polkavm.Gas, regs polkavm.Registers, mm polkavm.Memory, x service.ServiceAccount) (polkavm.Gas, polkavm.Registers, polkavm.Memory, service.ServiceAccount, error) {
		gasCounterOut, regsOut, memOut, ctxOut, err := host_call.Poke(
			gasCounter,
			regs,
			mm,
			ctxPair,
		)
		require.NoError(t, err)
		ctxPair = ctxOut
		return gasCounterOut, regsOut, memOut, x, err
	}

	gasRemaining, regsOut, _, _, err := interpreter.InvokeHostCall(pp, 0, initialGas, initialRegs, mem, hostCall, service.ServiceAccount{})
	require.ErrorIs(t, err, polkavm.ErrHalt)

	assert.Equal(t, uint64(host_call.OK), regsOut[polkavm.A0])

	actual := make([]byte, z)
	vm := ctxPair.IntegratedPVMMap[n]
	err = (&vm.Ram).Read(uint32(o), actual)
	require.NoError(t, err)
	expected := sourceData[:z]
	assert.Equal(t, expected, actual)

	expectedGasRemaining := polkavm.Gas(initialGas) - host_call.PokeCost - polkavm.GasCosts[polkavm.Ecalli] - polkavm.GasCosts[polkavm.JumpIndirect]
	assert.Equal(t, expectedGasRemaining, gasRemaining)
}

func TestZero(t *testing.T) {
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
	innerMem, _, err := polkavm.InitializeStandardProgram(pp, nil)
	require.NoError(t, err)

	n := uint64(0)
	p := uint64(32)
	c := uint64(2) // zero out pages #32 & #33

	startAddr := p * uint64(polkavm.PageSize)
	endAddr := (p + c) * uint64(polkavm.PageSize)

	for addr := startAddr; addr < endAddr; addr++ {
		err := mem.Write(uint32(addr), []byte{0xFF})
		require.NoError(t, err)
	}

	ctxPair := polkavm.RefineContextPair{
		IntegratedPVMMap: map[uint64]polkavm.IntegratedPVM{n: {Ram: innerMem}},
	}

	initialRegs[polkavm.A0] = n
	initialRegs[polkavm.A1] = p
	initialRegs[polkavm.A2] = c

	hostCallFn := func(
		hc uint32,
		gasCounter polkavm.Gas,
		regs polkavm.Registers,
		mm polkavm.Memory,
		acc service.ServiceAccount,
	) (polkavm.Gas, polkavm.Registers, polkavm.Memory, service.ServiceAccount, error) {

		gasOut, regsOut, memOut, ctxOut, err := host_call.Zero(
			gasCounter,
			regs,
			mm,
			ctxPair,
		)
		require.NoError(t, err)

		ctxPair = ctxOut
		return gasOut, regsOut, memOut, acc, err
	}

	gasRemaining, regsOut, _, _, err := interpreter.InvokeHostCall(
		pp,
		0,
		initialGas,
		initialRegs,
		mem,
		hostCallFn,
		service.ServiceAccount{},
	)
	require.ErrorIs(t, err, polkavm.ErrHalt)
	require.Equal(t, uint64(host_call.OK), regsOut[polkavm.A0])

	for addr := startAddr; addr < endAddr; addr++ {
		b := make([]byte, 1)
		innerPVMRam := ctxPair.IntegratedPVMMap[n].Ram
		err = innerPVMRam.Read(uint32(addr), b)
		require.NoError(t, err)
		assert.Equal(t, byte(0), b[0])
	}

	expectedGasRemaining := polkavm.Gas(initialGas) -
		host_call.ZeroCost -
		polkavm.GasCosts[polkavm.Ecalli] -
		polkavm.GasCosts[polkavm.JumpIndirect]
	assert.Equal(t, expectedGasRemaining, gasRemaining)
}

func TestVoid(t *testing.T) {
	pp := &polkavm.Program{
		ProgramMemorySizes: polkavm.ProgramMemorySizes{
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

	mem, initialRegs, err := polkavm.InitializeStandardProgram(pp, nil)
	require.NoError(t, err)
	innerMem, _, err := polkavm.InitializeStandardProgram(pp, nil)
	require.NoError(t, err)

	p := uint64(32)
	c := uint64(2)

	for pageIndex := p; pageIndex < p+c; pageIndex++ {
		access := mem.GetAccess(uint32(pageIndex))
		assert.Equal(t, polkavm.ReadWrite, access)
	}

	n := uint64(0)
	ctxPair := polkavm.RefineContextPair{
		IntegratedPVMMap: map[uint64]polkavm.IntegratedPVM{n: {Ram: innerMem}},
	}

	initialRegs[polkavm.A0] = n
	initialRegs[polkavm.A1] = p
	initialRegs[polkavm.A2] = c

	hostCall := func(hc uint32, gasCounter polkavm.Gas, regs polkavm.Registers,
		mm polkavm.Memory, x service.ServiceAccount,
	) (polkavm.Gas, polkavm.Registers, polkavm.Memory, service.ServiceAccount, error) {

		gasOut, regsOut, memOut, ctxOut, err := host_call.Void(
			gasCounter,
			regs,
			mm,
			ctxPair,
		)
		require.NoError(t, err)
		ctxPair = ctxOut
		return gasOut, regsOut, memOut, x, err
	}

	gasRemaining, regsOut, _, _, err := interpreter.InvokeHostCall(
		pp,
		0,
		initialGas,
		initialRegs,
		mem,
		hostCall,
		service.ServiceAccount{},
	)
	require.ErrorIs(t, err, polkavm.ErrHalt)

	require.Equal(t, uint64(host_call.OK), regsOut[polkavm.A0])

	for pageIndex := p; pageIndex < p+c; pageIndex++ {
		innerPVMRam := ctxPair.IntegratedPVMMap[n].Ram
		access := innerPVMRam.GetAccess(uint32(pageIndex))
		assert.Equal(t, polkavm.Inaccessible, access)
	}

	expectedGasRemaining := polkavm.Gas(initialGas) -
		host_call.VoidCost -
		polkavm.GasCosts[polkavm.Ecalli] -
		polkavm.GasCosts[polkavm.JumpIndirect]
	assert.Equal(t, expectedGasRemaining, gasRemaining)
}

func TestInvoke(t *testing.T) {
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

	bb, err := jam.Marshal([14]uint64{
		10000, // gas
		0,     // regs
		0,
		0,
		0,
		0,
		0,
		0,
		1,
		2,
		0,
		0,
		0,
		0,
	})
	require.NoError(t, err)

	addr := polkavm.RWAddressBase
	if err := mem.Write(addr, bb); err != nil {
		t.Fatal(err)
	}

	pvmKey := uint64(0)

	ctxPair := polkavm.RefineContextPair{
		IntegratedPVMMap: map[uint64]polkavm.IntegratedPVM{pvmKey: {
			Code:               addInstrProgram,
			Ram:                polkavm.Memory{}, // we don't use memory in tests yet
			InstructionCounter: 0,
		}},
	}

	initialRegs[polkavm.A0] = pvmKey
	initialRegs[polkavm.A1] = uint64(addr)

	hostCall := func(hc uint32, gasCounter polkavm.Gas, regs polkavm.Registers,
		mm polkavm.Memory, x struct{},
	) (polkavm.Gas, polkavm.Registers, polkavm.Memory, struct{}, error) {
		gasOut, regsOut, memOut, ctxOut, err := host_call.Invoke(gasCounter, regs, mm, ctxPair)
		require.NoError(t, err)
		ctxPair = ctxOut
		return gasOut, regsOut, memOut, x, err
	}

	gasRemaining, regsOut, _, _, err := interpreter.InvokeHostCall(
		pp,
		0,
		initialGas,
		initialRegs,
		mem,
		hostCall,
		struct{}{},
	)
	require.ErrorIs(t, err, polkavm.ErrHalt)

	assert.Equal(t, uint64(host_call.PANIC), regsOut[polkavm.A0])

	expectedGasRemaining := polkavm.Gas(initialGas) -
		host_call.InvokeCost -
		polkavm.GasCosts[polkavm.Ecalli] -
		polkavm.GasCosts[polkavm.JumpIndirect]
	assert.Equal(t, expectedGasRemaining, gasRemaining)

	invokeResult := make([]byte, 112)
	err = mem.Read(addr, invokeResult)
	require.NoError(t, err)

	invokeGasAndRegs := [14]uint64{}
	err = jam.Unmarshal(invokeResult, &invokeGasAndRegs)
	require.NoError(t, err)

	assert.Equal(t, uint32(3), ctxPair.IntegratedPVMMap[pvmKey].InstructionCounter)
	assert.Equal(t, uint64(9998), invokeGasAndRegs[0])
	assert.Equal(t, []uint64{0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 0, 0, 0}, invokeGasAndRegs[1:])
}

var addInstrProgram = []byte{0, 0, 3, 190, 135, 9, 1} // copied from the future testvectors :P

func TestExpunge(t *testing.T) {
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

	n, ic := uint64(7), uint32(42)

	ctxPair := polkavm.RefineContextPair{
		IntegratedPVMMap: make(map[uint64]polkavm.IntegratedPVM),
	}

	ctxPair.IntegratedPVMMap[n] = polkavm.IntegratedPVM{
		Ram:                mem,
		InstructionCounter: ic,
	}

	initialRegs[polkavm.A0] = n

	hostCallFn := func(hc uint32, gasCounter polkavm.Gas, regs polkavm.Registers,
		mm polkavm.Memory, x service.ServiceAccount,
	) (polkavm.Gas, polkavm.Registers, polkavm.Memory, service.ServiceAccount, error) {
		gasOut, regsOut, memOut, ctxOut, err := host_call.Expunge(
			gasCounter,
			regs,
			mm,
			ctxPair,
		)
		require.NoError(t, err)
		ctxPair = ctxOut
		return gasOut, regsOut, memOut, x, err
	}

	gasRemaining, regsOut, _, _, err := interpreter.InvokeHostCall(
		pp,
		0,
		100,
		initialRegs,
		mem,
		hostCallFn,
		service.ServiceAccount{},
	)
	require.ErrorIs(t, err, polkavm.ErrHalt)

	assert.Equal(t, uint64(ic), regsOut[polkavm.A0])

	expectedGasRemaining := polkavm.Gas(100) -
		host_call.ExpungeCost -
		polkavm.GasCosts[polkavm.Ecalli] -
		polkavm.GasCosts[polkavm.JumpIndirect]

	assert.Equal(t, expectedGasRemaining, gasRemaining)
}
