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
	}

	k, err := statekey.NewPreimageMeta(serviceId, crypto.Hash(hashKey), uint32(len(preimage)))
	require.NoError(t, err)

	err = sa.InsertPreimageMeta(k, uint64(len(preimage)), service.PreimageHistoricalTimeslots{0, 10})
	require.NoError(t, err)

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
	assert.Equal(t, uint64(i), vm.InstructionCounter)

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
	require.True(t, uDataBase+uint64(len(uData)) < math.MaxUint32)

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

	err = mem.Write(s, sourceData)
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
	err = (&vm.Ram).Read(o, actual)
	require.NoError(t, err)
	expected := sourceData[:z]
	assert.Equal(t, expected, actual)

	assert.Equal(t, polkavm.Gas(90), gasRemaining)
}

func TestPages_Modes(t *testing.T) {
	pp := &polkavm.Program{
		ProgramMemorySizes: polkavm.ProgramMemorySizes{
			RWDataSize:       256,
			StackSize:        512,
			InitialHeapPages: 100,
		},
	}

	for _, tc := range []struct {
		name       string
		mode       uint64
		wantAccess polkavm.MemoryAccess
		wantZeroed bool
	}{
		{
			name:       "mode_0", // Inaccessible
			mode:       0,
			wantAccess: polkavm.Inaccessible,
			wantZeroed: true,
		},
		{
			name:       "mode_1", // ReadOnly
			mode:       1,
			wantAccess: polkavm.ReadOnly,
			wantZeroed: true,
		},
		{
			name:       "mode_2", // ReadWrite
			mode:       2,
			wantAccess: polkavm.ReadWrite,
			wantZeroed: true,
		},
		{
			name:       "mode_3", // ReadOnly
			mode:       3,
			wantAccess: polkavm.ReadOnly,
			wantZeroed: false,
		},
		{
			name:       "mode_4", // ReadWrite
			mode:       4,
			wantAccess: polkavm.ReadWrite,
			wantZeroed: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mem, initialRegs, err := polkavm.InitializeStandardProgram(pp, nil)
			require.NoError(t, err)

			innerMem, _, err := polkavm.InitializeStandardProgram(pp, nil)
			require.NoError(t, err)

			p := uint64(32)
			c := uint64(2)

			// Pre-fill target pages with known values for zeroing check
			for pageIndex := p; pageIndex < p+c; pageIndex++ {
				start := pageIndex * uint64(polkavm.PageSize)
				buf := make([]byte, polkavm.PageSize)
				for i := range buf {
					buf[i] = 0xAB
				}
				err := innerMem.Write(start, buf)
				require.NoError(t, err)
			}

			n := uint64(0)
			ctxPair := polkavm.RefineContextPair{
				IntegratedPVMMap: map[uint64]polkavm.IntegratedPVM{n: {Ram: innerMem}},
			}

			initialRegs[polkavm.A0] = n
			initialRegs[polkavm.A1] = p
			initialRegs[polkavm.A2] = c
			initialRegs[polkavm.A3] = tc.mode

			gasRemaining, regsOut, _, _, err := host_call.Pages(
				initialGas,
				initialRegs,
				mem,
				ctxPair,
			)
			require.NoError(t, err)
			require.Equal(t, uint64(host_call.OK), regsOut[polkavm.A0])

			innerPVMRam := ctxPair.IntegratedPVMMap[n].Ram
			for pageIndex := p; pageIndex < p+c; pageIndex++ {
				access := innerPVMRam.GetAccess(pageIndex)
				assert.Equal(t, tc.wantAccess, access)
			}

			assert.Equal(t, polkavm.Gas(90), gasRemaining)
		})
	}
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

	assert.Equal(t, uint64(3), ctxPair.IntegratedPVMMap[pvmKey].InstructionCounter)
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

	n, ic := uint64(7), uint64(42)

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
