package host_call_test

import (
	"errors"
	"math"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/eigerco/strawberry/internal/block"
	"github.com/eigerco/strawberry/internal/constants"
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/jamtime"
	"github.com/eigerco/strawberry/internal/pvm"
	"github.com/eigerco/strawberry/internal/pvm/host_call"
	"github.com/eigerco/strawberry/internal/service"
	"github.com/eigerco/strawberry/internal/state/serialization/statekey"
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
	pp := &pvm.Program{
		ProgramMemorySizes: pvm.ProgramMemorySizes{
			RWDataSize:       256,
			StackSize:        512,
			InitialHeapPages: 10,
		},
	}

	mem, initialRegs, err := pvm.InitializeStandardProgram(pp, nil)
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
	}

	k, err := statekey.NewPreimageMeta(serviceId, crypto.Hash(hashKey), uint32(len(preimage)))
	require.NoError(t, err)

	err = sa.InsertPreimageMeta(k, uint64(len(preimage)), service.PreimageHistoricalTimeslots{0, 10})
	require.NoError(t, err)

	serviceState := service.ServiceState{
		serviceId: sa,
	}

	ho := pvm.RWAddressBase
	bo := pvm.RWAddressBase + 100
	offset := uint64(0)
	length := uint64(len(preimage))

	initialRegs[pvm.A0] = uint64(serviceId)
	initialRegs[pvm.A1] = uint64(ho)
	initialRegs[pvm.A2] = uint64(bo)
	initialRegs[pvm.A3] = offset
	initialRegs[pvm.A4] = length

	err = mem.Write(uint32(ho), hashKey[:])
	require.NoError(t, err)

	ctxPair := pvm.RefineContextPair{
		IntegratedPVMMap: make(map[uint64]pvm.IntegratedPVM),
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
	err = memOut.Read(uint32(bo), actualValue)
	require.NoError(t, err)

	assert.Equal(t, preimage, actualValue)
	assert.Equal(t, uint64(len(preimage)), regsOut[pvm.A0])

	assert.Equal(t, pvm.Gas(90), gasRemaining)
}

func TestExport(t *testing.T) {
	pp := &pvm.Program{
		ProgramMemorySizes: pvm.ProgramMemorySizes{
			RWDataSize:       256,
			StackSize:        512,
			InitialHeapPages: 10,
		},
	}

	mem, initialRegs, err := pvm.InitializeStandardProgram(pp, nil)
	require.NoError(t, err)

	dataToExport := []byte("export_data")
	p := pvm.RWAddressBase

	err = mem.Write(uint32(p), dataToExport)
	require.NoError(t, err)

	exportOffset := uint64(10)

	initialRegs[pvm.A0] = uint64(p)
	initialRegs[pvm.A1] = uint64(len(dataToExport))

	ctxPair := pvm.RefineContextPair{
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
	// We expect φ7 = ς + |e| = 10 + 1 = 11
	assert.Equal(t, exportOffset+1, regsOut[pvm.A0])

	require.Len(t, ctxPair.Segments, 1)
	seg := ctxPair.Segments[0]
	expectedSegment := make([]byte, constants.SizeOfSegment)
	copy(expectedSegment, dataToExport)
	assert.Equal(t, expectedSegment, seg[:])

	assert.Equal(t, pvm.Gas(90), gasRemaining)
}

func TestMachine(t *testing.T) {
	pp := &pvm.Program{
		ProgramMemorySizes: pvm.ProgramMemorySizes{
			RWDataSize:       256,
			StackSize:        512,
			InitialHeapPages: 10,
		},
	}

	mem, initialRegs, err := pvm.InitializeStandardProgram(pp, nil)
	require.NoError(t, err)

	p := []byte{0, 0, 3, 8, 135, 9, 1}
	po := pvm.RWAddressBase
	pz := len(p)
	i := uint64(42)

	err = mem.Write(uint32(po), p)
	require.NoError(t, err)

	initialRegs[pvm.A0] = uint64(po)
	initialRegs[pvm.A1] = uint64(pz)
	initialRegs[pvm.A2] = i

	ctxPair := pvm.RefineContextPair{
		IntegratedPVMMap: make(map[uint64]pvm.IntegratedPVM),
		Segments:         []work.Segment{},
	}

	gasRemaining, regsOut, _, _, err := host_call.Machine(
		initialGas,
		initialRegs,
		mem,
		ctxPair,
	)
	require.NoError(t, err)

	assert.Equal(t, uint64(0), regsOut[pvm.A0])

	require.Len(t, ctxPair.IntegratedPVMMap, 1)
	vm, exists := ctxPair.IntegratedPVMMap[0]
	require.True(t, exists)

	assert.Equal(t, p, vm.Code)
	assert.Equal(t, uint64(i), vm.InstructionCounter)

	assert.Equal(t, pvm.Gas(90), gasRemaining)
}

func TestPeek(t *testing.T) {
	pp := &pvm.Program{
		ProgramMemorySizes: pvm.ProgramMemorySizes{
			RWDataSize:       256,
			StackSize:        512,
			InitialHeapPages: 10,
		},
	}

	mem, initialRegs, err := pvm.InitializeStandardProgram(pp, nil)
	require.NoError(t, err)

	n := uint64(0)
	o := pvm.RWAddressBase + 100
	z := uint64(1)

	uData := []byte("data_for_peek")

	uDataBase := pvm.RWAddressBase
	require.True(t, uDataBase+uint64(len(uData)) < math.MaxUint32)

	err = mem.Write(uint32(uDataBase), uData)
	require.NoError(t, err)

	s := uint64(uDataBase) + 10

	u := pvm.IntegratedPVM{
		Code:               nil,
		Ram:                mem,
		InstructionCounter: 0,
	}

	ctxPair := pvm.RefineContextPair{
		IntegratedPVMMap: map[uint64]pvm.IntegratedPVM{
			n: u,
		},
		Segments: []work.Segment{},
	}

	initialRegs[pvm.A0] = n
	initialRegs[pvm.A1] = uint64(o)
	initialRegs[pvm.A2] = s
	initialRegs[pvm.A3] = z

	gasRemaining, regsOut, memOut, _, err := host_call.Peek(
		initialGas,
		initialRegs,
		mem,
		ctxPair,
	)
	require.NoError(t, err)

	assert.Equal(t, uint64(host_call.OK), regsOut[pvm.A0])

	actualValue := make([]byte, z)
	err = memOut.Read(uint32(o), actualValue)
	require.NoError(t, err)

	startOffset := s - uint64(uDataBase)
	endOffset := startOffset + z
	expectedValue := uData[startOffset:endOffset]
	assert.Equal(t, expectedValue, actualValue)

	assert.Equal(t, pvm.Gas(90), gasRemaining)
}

func TestPoke(t *testing.T) {
	pp := &pvm.Program{
		ProgramMemorySizes: pvm.ProgramMemorySizes{
			RWDataSize:       256,
			StackSize:        512,
			InitialHeapPages: 10,
		},
	}

	mem, initialRegs, err := pvm.InitializeStandardProgram(pp, nil)
	require.NoError(t, err)

	n := uint64(0)
	s := uint64(pvm.RWAddressBase) + 100
	o := uint64(pvm.RWAddressBase) + 200
	z := uint64(4)

	sourceData := []byte("data_for_poke")

	err = mem.Write(uint32(s), sourceData)
	require.NoError(t, err)

	u := pvm.IntegratedPVM{
		Code:               nil,
		Ram:                mem,
		InstructionCounter: 0,
	}

	ctxPair := pvm.RefineContextPair{
		IntegratedPVMMap: map[uint64]pvm.IntegratedPVM{
			n: u,
		},
		Segments: []work.Segment{},
	}

	initialRegs[pvm.A0] = n
	initialRegs[pvm.A1] = s
	initialRegs[pvm.A2] = o
	initialRegs[pvm.A3] = z

	gasRemaining, regsOut, _, _, err := host_call.Poke(
		initialGas,
		initialRegs,
		mem,
		ctxPair,
	)
	require.NoError(t, err)

	assert.Equal(t, uint64(host_call.OK), regsOut[pvm.A0])

	actual := make([]byte, z)
	vm := ctxPair.IntegratedPVMMap[n]
	err = (&vm.Ram).Read(uint32(o), actual)
	require.NoError(t, err)
	expected := sourceData[:z]
	assert.Equal(t, expected, actual)

	assert.Equal(t, pvm.Gas(90), gasRemaining)
}

func TestPages_Modes(t *testing.T) {
	pp := &pvm.Program{
		ProgramMemorySizes: pvm.ProgramMemorySizes{
			RWDataSize:       256,
			StackSize:        512,
			InitialHeapPages: 100,
		},
	}

	for _, tc := range []struct {
		name       string
		mode       uint64
		wantAccess pvm.MemoryAccess
		wantZeroed bool
	}{
		{
			name:       "mode_0", // Inaccessible
			mode:       0,
			wantAccess: pvm.Inaccessible,
			wantZeroed: true,
		},
		{
			name:       "mode_1", // ReadOnly
			mode:       1,
			wantAccess: pvm.ReadOnly,
			wantZeroed: true,
		},
		{
			name:       "mode_2", // ReadWrite
			mode:       2,
			wantAccess: pvm.ReadWrite,
			wantZeroed: true,
		},
		{
			name:       "mode_3", // ReadOnly
			mode:       3,
			wantAccess: pvm.ReadOnly,
			wantZeroed: false,
		},
		{
			name:       "mode_4", // ReadWrite
			mode:       4,
			wantAccess: pvm.ReadWrite,
			wantZeroed: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mem, initialRegs, err := pvm.InitializeStandardProgram(pp, nil)
			require.NoError(t, err)

			innerMem, _, err := pvm.InitializeStandardProgram(pp, nil)
			require.NoError(t, err)

			p := uint64(32)
			c := uint64(2)

			// Pre-fill target pages with known values for zeroing check
			for pageIndex := p; pageIndex < p+c; pageIndex++ {
				start := pageIndex * uint64(pvm.PageSize)
				buf := make([]byte, pvm.PageSize)
				for i := range buf {
					buf[i] = 0xAB
				}
				err := innerMem.Write(uint32(start), buf)
				require.NoError(t, err)
			}

			n := uint64(0)
			ctxPair := pvm.RefineContextPair{
				IntegratedPVMMap: map[uint64]pvm.IntegratedPVM{n: {Ram: innerMem}},
			}

			initialRegs[pvm.A0] = n
			initialRegs[pvm.A1] = p
			initialRegs[pvm.A2] = c
			initialRegs[pvm.A3] = tc.mode

			gasRemaining, regsOut, _, _, err := host_call.Pages(
				initialGas,
				initialRegs,
				mem,
				ctxPair,
			)
			require.NoError(t, err)
			require.Equal(t, uint64(host_call.OK), regsOut[pvm.A0])

			innerPVMRam := ctxPair.IntegratedPVMMap[n].Ram
			for pageIndex := p; pageIndex < p+c; pageIndex++ {
				access := innerPVMRam.GetAccess(uint32(pageIndex))
				assert.Equal(t, tc.wantAccess, access)
			}

			assert.Equal(t, pvm.Gas(90), gasRemaining)
		})
	}
}

func TestInvoke(t *testing.T) {
	pp := &pvm.Program{
		ProgramMemorySizes: pvm.ProgramMemorySizes{
			RWDataSize:       256,
			StackSize:        512,
			InitialHeapPages: 10,
		},
	}

	mem, initialRegs, err := pvm.InitializeStandardProgram(pp, nil)
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

	addr := pvm.RWAddressBase
	if err := mem.Write(uint32(addr), bb); err != nil {
		t.Fatal(err)
	}

	pvmKey := uint64(0)

	ctxPair := pvm.RefineContextPair{
		IntegratedPVMMap: map[uint64]pvm.IntegratedPVM{pvmKey: {
			Code:               addInstrProgram,
			Ram:                pvm.Memory{}, // we don't use memory in tests yet
			InstructionCounter: 0,
		}},
	}

	initialRegs[pvm.A0] = pvmKey
	initialRegs[pvm.A1] = uint64(addr)

	gasRemaining, regsOut, _, _, err := host_call.Invoke(initialGas, initialRegs, mem, ctxPair)
	require.NoError(t, err)
	assert.Equal(t, uint64(host_call.PANIC), regsOut[pvm.A0])

	assert.Equal(t, pvm.Gas(90), gasRemaining)

	invokeResult := make([]byte, 112)
	err = mem.Read(uint32(addr), invokeResult)
	require.NoError(t, err)

	invokeGasAndRegs := [14]uint64{}
	err = jam.Unmarshal(invokeResult, &invokeGasAndRegs)
	require.NoError(t, err)

	assert.Equal(t, uint64(3), ctxPair.IntegratedPVMMap[pvmKey].InstructionCounter)
	assert.Equal(t, uint64(9998), invokeGasAndRegs[0])
	assert.Equal(t, []uint64{0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 0, 0, 0}, invokeGasAndRegs[1:])
}

var addInstrProgram = []byte{0, 0, 3, 190, 135, 9, 1} // copied from the future testvectors :P

func TestExpunge(t *testing.T) {
	pp := &pvm.Program{
		ProgramMemorySizes: pvm.ProgramMemorySizes{
			RWDataSize:       256,
			StackSize:        512,
			InitialHeapPages: 10,
		},
	}

	mem, initialRegs, err := pvm.InitializeStandardProgram(pp, nil)
	require.NoError(t, err)

	n, ic := uint64(7), uint64(42)

	ctxPair := pvm.RefineContextPair{
		IntegratedPVMMap: make(map[uint64]pvm.IntegratedPVM),
	}

	ctxPair.IntegratedPVMMap[n] = pvm.IntegratedPVM{
		Ram:                mem,
		InstructionCounter: ic,
	}

	initialRegs[pvm.A0] = n

	gasRemaining, regsOut, _, _, err := host_call.Expunge(
		initialGas,
		initialRegs,
		mem,
		ctxPair,
	)
	require.NoError(t, err)
	assert.Equal(t, uint64(ic), regsOut[pvm.A0])

	assert.Equal(t, pvm.Gas(90), gasRemaining)
}
