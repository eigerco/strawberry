package host_call_test

import (
	"errors"
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
	"github.com/eigerco/strawberry/internal/service"
	"github.com/eigerco/strawberry/internal/work"
	"github.com/eigerco/strawberry/pkg/serialization/codec/jam"
)

type MockPreimageFetcher struct {
	fetchedPreimage map[crypto.Hash][]byte
}

func (m *MockPreimageFetcher) FetchPreimage(hash crypto.Hash) ([]byte, error) {
	preimage, exists := m.fetchedPreimage[hash]
	if !exists {
		return nil, errors.New("preimage not found")
	}
	return preimage, nil
}

const initialGas = 100

func TestHistoricalLookup(t *testing.T) {
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
	timeslot := jamtime.Timeslot(9)

	preimage := []byte("historical_data")
	hashKey := make([]byte, 32)
	copy(hashKey, preimage)

	sa := service.ServiceAccount{
		PreimageLookup: map[crypto.Hash][]byte{
			crypto.Hash(hashKey): preimage,
		},
		PreimageMeta: map[service.PreImageMetaKey]service.PreimageHistoricalTimeslots{
			{
				Hash:   crypto.Hash(hashKey),
				Length: service.PreimageLength(len(preimage)),
			}: {0, 10},
		},
	}

	serviceState := service.ServiceState{
		serviceId: sa,
	}

	ho := polkavm.RWAddressBase
	bo := polkavm.RWAddressBase + 100
	offset := uint64(0)
	length := uint64(len(preimage))

	initialRegs[polkavm.A0] = uint64(serviceId)
	initialRegs[polkavm.A1] = uint64(ho)
	initialRegs[polkavm.A2] = uint64(bo)
	initialRegs[polkavm.A3] = offset
	initialRegs[polkavm.A4] = length

	err = mem.Write(ho, hashKey[:])
	require.NoError(t, err)

	ctxPair := polkavm.RefineContextPair{
		IntegratedPVMMap: make(map[uint64]polkavm.IntegratedPVM),
		Segments:         []work.Segment{},
	}

	gasRemaining, regsOut, memOut, _, err := host_call.HistoricalLookup(
		initialGas,
		initialRegs,
		mem,
		ctxPair,
		serviceId,
		serviceState,
		timeslot,
	)
	require.NoError(t, err)

	actualValue := make([]byte, len(preimage))
	err = memOut.Read(bo, actualValue)
	require.NoError(t, err)

	assert.Equal(t, preimage, actualValue)
	assert.Equal(t, uint64(len(preimage)), regsOut[polkavm.A0])

	assert.Equal(t, polkavm.Gas(90), gasRemaining)
}

func TestFetch(t *testing.T) {
	pp := &polkavm.Program{
		ProgramMemorySizes: polkavm.ProgramMemorySizes{
			RWDataSize:       256,
			StackSize:        512,
			InitialHeapPages: 10,
		},
	}

	mem, initialRegs, err := polkavm.InitializeStandardProgram(pp, nil)
	require.NoError(t, err)

	parameterization := []byte("parameterization_data")
	workItemPayload := []byte("work_item_payload")
	workItemExtrinsic := work.Extrinsic{
		Hash:   crypto.HashData([]byte("extrinsic_hash")),
		Length: uint32(len([]byte("extrinsic_data"))),
	}

	workPackage := work.Package{
		Parameterization: parameterization,
		WorkItems: []work.Item{
			{
				Payload:    workItemPayload,
				Extrinsics: []work.Extrinsic{workItemExtrinsic},
			},
		},
	}

	importedSegments := []work.Segment{
		{1, 2, 3, 4, 5, 6, 7, 8},
		{9, 10, 11, 12, 13, 14},
	}

	authorizerHashOutput := []byte("auth_hash_output")

	ho := polkavm.RWAddressBase + 100
	mode := uint64(0)
	offset := uint64(0)
	length := uint64(64)

	initialRegs[polkavm.A0] = uint64(ho)
	initialRegs[polkavm.A1] = offset
	initialRegs[polkavm.A2] = length
	initialRegs[polkavm.A3] = mode

	itemIndex := uint32(0)

	ctxPair := polkavm.RefineContextPair{
		Segments: []work.Segment{},
	}

	preimageData := "extrinsic_preimage_data"
	preimageDataLength := uint64(len(preimageData))

	mockFetcher := &MockPreimageFetcher{
		fetchedPreimage: map[crypto.Hash][]byte{
			workItemExtrinsic.Hash: []byte(preimageData),
		},
	}

	expectedGasRemaining := polkavm.Gas(90)

	t.Run("Fetch DataID 0 (Encoding Work Package)", func(t *testing.T) {
		gasRemaining, regsOut, memOut, _, err := host_call.Fetch(
			initialGas,
			initialRegs,
			mem,
			ctxPair,
			itemIndex,
			workPackage,
			authorizerHashOutput,
			importedSegments,
			nil,
		)
		require.NoError(t, err)

		encodedWorkPackage, err := jam.Marshal(workPackage)
		require.NoError(t, err)

		expectedSize := min(len(encodedWorkPackage), int(length))
		expectedData := encodedWorkPackage[:expectedSize]

		actualValue := make([]byte, expectedSize)
		err = memOut.Read(ho, actualValue)
		require.NoError(t, err)

		require.Equal(t, expectedData, actualValue)
		require.Equal(t, uint64(len(encodedWorkPackage)), regsOut[polkavm.A0])

		require.Equal(t, expectedGasRemaining, gasRemaining)
	})

	t.Run("Fetch DataID 1 (Authorizer Hash Output)", func(t *testing.T) {
		initialRegs[polkavm.A3] = 1

		gasRemaining, regsOut, memOut, _, err := host_call.Fetch(
			initialGas,
			initialRegs,
			mem,
			ctxPair,
			itemIndex,
			workPackage,
			authorizerHashOutput,
			importedSegments,
			nil,
		)
		require.NoError(t, err)

		actualValue := make([]byte, len(authorizerHashOutput))
		err = memOut.Read(ho, actualValue)
		require.NoError(t, err)

		require.Equal(t, authorizerHashOutput, actualValue)
		require.Equal(t, uint64(len(authorizerHashOutput)), regsOut[polkavm.A0])

		require.Equal(t, expectedGasRemaining, gasRemaining)
	})

	t.Run("Fetch DataID 2 (Work Item Payload)", func(t *testing.T) {
		initialRegs[polkavm.A3] = 2
		initialRegs[polkavm.A4] = 0

		gasRemaining, regsOut, memOut, _, err := host_call.Fetch(
			initialGas,
			initialRegs,
			mem,
			ctxPair,
			itemIndex,
			workPackage,
			authorizerHashOutput,
			importedSegments,
			nil,
		)
		require.NoError(t, err)

		actualValue := make([]byte, len(workItemPayload))
		err = memOut.Read(ho, actualValue)
		require.NoError(t, err)

		require.Equal(t, workItemPayload, actualValue)
		require.Equal(t, uint64(len(workItemPayload)), regsOut[polkavm.A0])

		require.Equal(t, expectedGasRemaining, gasRemaining)
	})

	t.Run("Fetch DataID 3 (Extrinsic Preimage)", func(t *testing.T) {
		initialRegs[polkavm.A3] = 3
		initialRegs[polkavm.A4] = 0
		initialRegs[polkavm.A5] = 0

		gasRemaining, regsOut, memOut, _, err := host_call.Fetch(
			initialGas,
			initialRegs,
			mem,
			ctxPair,
			itemIndex,
			workPackage,
			authorizerHashOutput,
			importedSegments,
			mockFetcher,
		)
		require.NoError(t, err)

		actualValue := make([]byte, preimageDataLength)
		err = memOut.Read(ho, actualValue)
		require.NoError(t, err)

		require.Equal(t, preimageData, string(actualValue))
		require.Equal(t, preimageDataLength, regsOut[polkavm.A0])
		require.Equal(t, expectedGasRemaining, gasRemaining)
	})

	t.Run("Fetch DataID 4 (Extrinsic Preimage)", func(t *testing.T) {
		initialRegs[polkavm.A3] = 4
		initialRegs[polkavm.A4] = 0
		itemIndex = 0

		gasRemaining, regsOut, memOut, _, err := host_call.Fetch(
			initialGas,
			initialRegs,
			mem,
			ctxPair,
			itemIndex,
			workPackage,
			authorizerHashOutput,
			importedSegments,
			mockFetcher,
		)
		require.NoError(t, err)

		actualValue := make([]byte, preimageDataLength)
		err = memOut.Read(ho, actualValue)
		require.NoError(t, err)

		require.Equal(t, preimageData, string(actualValue))
		require.Equal(t, preimageDataLength, regsOut[polkavm.A0])
		require.Equal(t, expectedGasRemaining, gasRemaining)
	})

	t.Run("Fetch DataID 5 (Imported Segments)", func(t *testing.T) {
		initialRegs[polkavm.A3] = 5
		initialRegs[polkavm.A4] = 0
		initialRegs[polkavm.A5] = 2

		gasRemaining, regsOut, memOut, _, err := host_call.Fetch(
			initialGas,
			initialRegs,
			mem,
			ctxPair,
			itemIndex,
			workPackage,
			authorizerHashOutput,
			importedSegments,
			nil,
		)
		require.NoError(t, err)

		actualValue := make([]byte, 1)
		err = memOut.Read(ho, actualValue)
		require.NoError(t, err)

		require.Equal(t, []byte{importedSegments[regsOut[polkavm.A4]][regsOut[polkavm.A5]]}, actualValue)
		require.Equal(t, uint64(1), regsOut[polkavm.A0])

		require.Equal(t, expectedGasRemaining, gasRemaining)
	})
	t.Run("Fetch DataID 6 (Imported Segments)", func(t *testing.T) {
		initialRegs[polkavm.A3] = 6
		initialRegs[polkavm.A4] = 1
		itemIndex = 1

		gasRemaining, regsOut, memOut, _, err := host_call.Fetch(
			initialGas,
			initialRegs,
			mem,
			ctxPair,
			itemIndex,
			workPackage,
			authorizerHashOutput,
			importedSegments,
			nil,
		)
		require.NoError(t, err)

		actualValue := make([]byte, 1)
		err = memOut.Read(ho, actualValue)
		require.NoError(t, err)

		require.Equal(t, []byte{importedSegments[itemIndex][regsOut[polkavm.A4]]}, actualValue)
		require.Equal(t, uint64(1), regsOut[polkavm.A0])

		require.Equal(t, expectedGasRemaining, gasRemaining)
	})

}

func TestExport(t *testing.T) {
	pp := &polkavm.Program{
		ProgramMemorySizes: polkavm.ProgramMemorySizes{
			RWDataSize:       256,
			StackSize:        512,
			InitialHeapPages: 10,
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
		Segments: []work.Segment{},
	}

	gasRemaining, regsOut, _, ctxPair, err := host_call.Export(
		initialGas,
		initialRegs,
		mem,
		ctxPair,
		exportOffset,
	)
	require.NoError(t, err)
	// We expect ω7 = ς + |e| = 10 + 1 = 11
	assert.Equal(t, exportOffset+1, regsOut[polkavm.A0])

	require.Len(t, ctxPair.Segments, 1)
	seg := ctxPair.Segments[0]
	expectedSegment := make([]byte, common.SizeOfSegment)
	copy(expectedSegment, dataToExport)
	assert.Equal(t, expectedSegment, seg[:])

	assert.Equal(t, polkavm.Gas(90), gasRemaining)
}

func TestMachine(t *testing.T) {
	pp := &polkavm.Program{
		ProgramMemorySizes: polkavm.ProgramMemorySizes{
			RWDataSize:       256,
			StackSize:        512,
			InitialHeapPages: 10,
		},
	}

	mem, initialRegs, err := polkavm.InitializeStandardProgram(pp, nil)
	require.NoError(t, err)

	p := []byte{0, 0, 3, 8, 135, 9, 1}
	po := polkavm.RWAddressBase
	pz := len(p)
	i := uint64(42)

	err = mem.Write(po, p)
	require.NoError(t, err)

	initialRegs[polkavm.A0] = uint64(po)
	initialRegs[polkavm.A1] = uint64(pz)
	initialRegs[polkavm.A2] = i

	ctxPair := polkavm.RefineContextPair{
		IntegratedPVMMap: make(map[uint64]polkavm.IntegratedPVM),
		Segments:         []work.Segment{},
	}

	gasRemaining, regsOut, _, _, err := host_call.Machine(
		initialGas,
		initialRegs,
		mem,
		ctxPair,
	)
	require.NoError(t, err)

	assert.Equal(t, uint64(0), regsOut[polkavm.A0])

	require.Len(t, ctxPair.IntegratedPVMMap, 1)
	vm, exists := ctxPair.IntegratedPVMMap[0]
	require.True(t, exists)

	assert.Equal(t, p, vm.Code)
	assert.Equal(t, uint32(i), vm.InstructionCounter)

	assert.Equal(t, polkavm.Gas(90), gasRemaining)
}

func TestPeek(t *testing.T) {
	pp := &polkavm.Program{
		ProgramMemorySizes: polkavm.ProgramMemorySizes{
			RWDataSize:       256,
			StackSize:        512,
			InitialHeapPages: 10,
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
		Segments: []work.Segment{},
	}

	initialRegs[polkavm.A0] = n
	initialRegs[polkavm.A1] = uint64(o)
	initialRegs[polkavm.A2] = s
	initialRegs[polkavm.A3] = z

	gasRemaining, regsOut, memOut, _, err := host_call.Peek(
		initialGas,
		initialRegs,
		mem,
		ctxPair,
	)
	require.NoError(t, err)

	assert.Equal(t, uint64(host_call.OK), regsOut[polkavm.A0])

	actualValue := make([]byte, z)
	err = memOut.Read(o, actualValue)
	require.NoError(t, err)

	startOffset := s - uint64(uDataBase)
	endOffset := startOffset + z
	expectedValue := uData[startOffset:endOffset]
	assert.Equal(t, expectedValue, actualValue)

	assert.Equal(t, polkavm.Gas(90), gasRemaining)
}

func TestPoke(t *testing.T) {
	pp := &polkavm.Program{
		ProgramMemorySizes: polkavm.ProgramMemorySizes{
			RWDataSize:       256,
			StackSize:        512,
			InitialHeapPages: 10,
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
		Segments: []work.Segment{},
	}

	initialRegs[polkavm.A0] = n
	initialRegs[polkavm.A1] = s
	initialRegs[polkavm.A2] = o
	initialRegs[polkavm.A3] = z

	gasRemaining, regsOut, _, _, err := host_call.Poke(
		initialGas,
		initialRegs,
		mem,
		ctxPair,
	)
	require.NoError(t, err)

	assert.Equal(t, uint64(host_call.OK), regsOut[polkavm.A0])

	actual := make([]byte, z)
	vm := ctxPair.IntegratedPVMMap[n]
	err = (&vm.Ram).Read(uint32(o), actual)
	require.NoError(t, err)
	expected := sourceData[:z]
	assert.Equal(t, expected, actual)

	assert.Equal(t, polkavm.Gas(90), gasRemaining)
}

func TestZero(t *testing.T) {
	pp := &polkavm.Program{
		ProgramMemorySizes: polkavm.ProgramMemorySizes{
			RWDataSize:       256,
			StackSize:        512,
			InitialHeapPages: 10,
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

	gasRemaining, regsOut, _, _, err := host_call.Zero(
		initialGas,
		initialRegs,
		mem,
		ctxPair,
	)
	require.NoError(t, err)

	require.Equal(t, uint64(host_call.OK), regsOut[polkavm.A0])
	for addr := startAddr; addr < endAddr; addr++ {
		b := make([]byte, 1)
		innerPVMRam := ctxPair.IntegratedPVMMap[n].Ram
		err = innerPVMRam.Read(uint32(addr), b)
		require.NoError(t, err)
		assert.Equal(t, byte(0), b[0])
	}

	assert.Equal(t, polkavm.Gas(90), gasRemaining)
}

func TestVoid(t *testing.T) {
	pp := &polkavm.Program{
		ProgramMemorySizes: polkavm.ProgramMemorySizes{
			RWDataSize:       256,
			StackSize:        512,
			InitialHeapPages: 100,
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

	gasRemaining, regsOut, _, _, err := host_call.Void(
		initialGas,
		initialRegs,
		mem,
		ctxPair,
	)
	require.NoError(t, err)
	require.Equal(t, uint64(host_call.OK), regsOut[polkavm.A0])

	for pageIndex := p; pageIndex < p+c; pageIndex++ {
		innerPVMRam := ctxPair.IntegratedPVMMap[n].Ram
		access := innerPVMRam.GetAccess(uint32(pageIndex))
		assert.Equal(t, polkavm.Inaccessible, access)
	}

	assert.Equal(t, polkavm.Gas(90), gasRemaining)
}

func TestInvoke(t *testing.T) {
	pp := &polkavm.Program{
		ProgramMemorySizes: polkavm.ProgramMemorySizes{
			RWDataSize:       256,
			StackSize:        512,
			InitialHeapPages: 10,
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

	gasRemaining, regsOut, _, _, err := host_call.Invoke(initialGas, initialRegs, mem, ctxPair)
	require.NoError(t, err)
	assert.Equal(t, uint64(host_call.PANIC), regsOut[polkavm.A0])

	assert.Equal(t, polkavm.Gas(90), gasRemaining)

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

	gasRemaining, regsOut, _, _, err := host_call.Expunge(
		initialGas,
		initialRegs,
		mem,
		ctxPair,
	)
	require.NoError(t, err)
	assert.Equal(t, uint64(ic), regsOut[polkavm.A0])

	assert.Equal(t, polkavm.Gas(90), gasRemaining)
}
