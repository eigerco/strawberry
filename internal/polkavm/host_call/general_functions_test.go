package host_call_test

import (
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/eigerco/strawberry/internal/block"
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/jamtime"
	"github.com/eigerco/strawberry/internal/polkavm"
	"github.com/eigerco/strawberry/internal/polkavm/host_call"
	"github.com/eigerco/strawberry/internal/service"
	"github.com/eigerco/strawberry/internal/state"
	"github.com/eigerco/strawberry/internal/state/serialization/statekey"
	"github.com/eigerco/strawberry/internal/testutils"
	"github.com/eigerco/strawberry/internal/work"
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

func TestFetch(t *testing.T) {
	pp := &polkavm.Program{
		ProgramMemorySizes: polkavm.ProgramMemorySizes{
			RWDataSize:       512,
			StackSize:        512,
			InitialHeapPages: 10,
		},
	}

	mem, regs, err := polkavm.InitializeStandardProgram(pp, nil)
	require.NoError(t, err)

	preimageBytes := testutils.RandomBytes(t, 32)

	importedSegments := []work.Segment{
		{1, 2, 3},
		{4, 5, 6},
		{7, 8, 9},
	}

	workPackage := &work.Package{
		AuthorizationToken: testutils.RandomBytes(t, 5),
		AuthorizerService:  1,
		AuthCodeHash:       testutils.RandomHash(t),
		Parameterization:   testutils.RandomBytes(t, 5),
		Context: block.RefinementContext{
			Anchor:                  block.RefinementContextAnchor{HeaderHash: testutils.RandomHash(t)},
			LookupAnchor:            block.RefinementContextLookupAnchor{HeaderHash: testutils.RandomHash(t), Timeslot: 125},
			PrerequisiteWorkPackage: nil,
		},
		WorkItems: []work.Item{
			{
				Payload:            testutils.RandomBytes(t, 10),
				GasLimitRefine:     100,
				GasLimitAccumulate: 100,
				Extrinsics:         []work.Extrinsic{},
				ImportedSegments:   []work.ImportedSegment{},
				ServiceId:          42,
				CodeHash:           testutils.RandomHash(t),
			},
		},
	}

	workPackageBytes, err := jam.Marshal(workPackage)
	require.NoError(t, err)

	authorizerHashOutput := testutils.RandomBytes(t, 32)
	extrinsicPreimages := [][]byte{preimageBytes}
	itemIndex := uint32(0)

	op1 := &state.AccumulationInput{}
	err = op1.SetValue(state.AccumulationOperand{Trace: testutils.RandomBytes(t, 5), OutputOrError: block.WorkResultOutputOrError{Inner: block.UnexpectedTermination}})
	require.NoError(t, err)

	transfer1 := &state.AccumulationInput{}
	err = transfer1.SetValue(service.DeferredTransfer{Balance: 101, Memo: [service.TransferMemoSizeBytes]byte{1, 2, 3}})
	require.NoError(t, err)

	transfer2 := &state.AccumulationInput{}
	err = transfer2.SetValue(service.DeferredTransfer{Balance: 100, Memo: [service.TransferMemoSizeBytes]byte{4, 5, 6}})
	require.NoError(t, err)

	operand := []*state.AccumulationInput{
		op1, transfer1, transfer2,
	}

	entropy := testutils.RandomHash(t)

	ho := polkavm.RWAddressBase + 100
	initialGas := polkavm.Gas(100)
	offset := uint64(0)
	length := uint64(512)

	cases := []struct {
		name   string
		dataID uint64
		idx1   uint64
		idx2   uint64
		expect func() []byte
	}{
		{
			name:   "dataID 0 (constants)",
			dataID: 0,
			expect: func() []byte {
				return host_call.GetChainConstants()
			},
		},
		{
			name:   "dataID 1 (entropy)",
			dataID: 1,
			expect: func() []byte { return entropy[:] },
		},
		{
			name:   "dataID 2 (authorizer hash)",
			dataID: 2,
			expect: func() []byte { return authorizerHashOutput },
		},
		{
			name:   "dataID 3 (preimages)",
			dataID: 3,
			idx1:   0,
			idx2:   0,
			expect: func() []byte {
				return []byte{preimageBytes[0]}
			},
		},
		{
			name:   "dataID 4 (preimages)",
			dataID: 4,
			idx1:   0,
			expect: func() []byte {
				return []byte{preimageBytes[0]}
			},
		},
		{
			name:   "dataID 5 (importedSegments)",
			dataID: 5,
			idx1:   1,
			idx2:   2,
			expect: func() []byte {
				return []byte{6}
			},
		},
		{
			name:   "dataID 6 (importedSegments)",
			dataID: 6,
			idx1:   2,
			expect: func() []byte {
				return []byte{3}
			},
		},
		{
			name:   "dataID 7 (work package)",
			dataID: 7,
			expect: func() []byte {
				return workPackageBytes
			},
		},
		{
			name:   "dataID 8 (AuthCodeHash + Parameterization)",
			dataID: 8,
			expect: func() []byte {
				return workPackage.Parameterization
			},
		},
		{
			name:   "dataID 9 (AuthorizationToken)",
			dataID: 9,
			expect: func() []byte {
				return workPackage.AuthorizationToken
			},
		},
		{
			name:   "dataID 10 (Context)",
			dataID: 10,
			expect: func() []byte {
				out, _ := jam.Marshal(workPackage.Context)
				return out
			},
		},
		{
			name:   "dataID 11 (all workItems)",
			dataID: 11,
			expect: func() []byte {
				var all [][]byte
				for _, item := range workPackage.WorkItems {
					meta := host_call.WorkItemMetadata{
						ServiceId:              item.ServiceId,
						CodeHash:               item.CodeHash,
						GasLimitRefine:         item.GasLimitRefine,
						GasLimitAccumulate:     item.GasLimitAccumulate,
						ExportedSegmentsLength: item.ExportedSegments,
						ImportedSegmentsLength: uint16(len(item.ImportedSegments)),
						ExtrinsicsLength:       uint16(len(item.Extrinsics)),
						PayloadLength:          uint32(len(item.Payload)),
					}
					b, _ := jam.Marshal(meta)
					all = append(all, b)
				}
				out, _ := jam.Marshal(all)
				return out
			},
		},
		{
			name:   "dataID 12 (specific workItem)",
			dataID: 12,
			idx1:   0,
			expect: func() []byte {
				item := workPackage.WorkItems[0]
				meta := host_call.WorkItemMetadata{
					ServiceId:              item.ServiceId,
					CodeHash:               item.CodeHash,
					GasLimitRefine:         item.GasLimitRefine,
					GasLimitAccumulate:     item.GasLimitAccumulate,
					ExportedSegmentsLength: item.ExportedSegments,
					ImportedSegmentsLength: uint16(len(item.ImportedSegments)),
					ExtrinsicsLength:       uint16(len(item.Extrinsics)),
					PayloadLength:          uint32(len(item.Payload)),
				}
				out, err := jam.Marshal(meta)
				require.NoError(t, err)

				return out
			},
		},
		{
			name:   "dataID 13 (Payload)",
			dataID: 13,
			idx1:   0,
			expect: func() []byte {
				return workPackage.WorkItems[0].Payload
			},
		},
		{
			name:   "dataID 14 (↕operand)",
			dataID: 14,
			expect: func() []byte {
				out, err := jam.Marshal(operand)
				require.NoError(t, err)

				return out
			},
		},
		{
			name:   "dataID 15 (operand[0])",
			dataID: 15,
			idx1:   0,
			expect: func() []byte {
				out, err := jam.Marshal(operand[0])
				require.NoError(t, err)

				return out
			},
		},
		{
			name:   "dataID 15 (operand[1])",
			dataID: 15,
			idx1:   1,
			expect: func() []byte {
				out, err := jam.Marshal(operand[1])
				require.NoError(t, err)

				return out
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			regs[polkavm.A0] = ho
			regs[polkavm.A1] = offset
			regs[polkavm.A2] = length
			regs[polkavm.A3] = tc.dataID
			regs[polkavm.A4] = tc.idx1
			regs[polkavm.A5] = tc.idx2

			expect := tc.expect()

			gasLeft, regsOut, memOut, err := host_call.Fetch(
				initialGas, regs, mem,
				workPackage, &entropy, authorizerHashOutput,
				&itemIndex, importedSegments, extrinsicPreimages,
				operand,
			)
			require.NoError(t, err)

			actual := make([]byte, len(expect))
			err = memOut.Read(uint32(ho), actual)
			require.NoError(t, err)
			require.Equal(t, expect, actual)
			require.Equal(t, uint64(len(expect)), regsOut[polkavm.A0])
			require.Equal(t, polkavm.Gas(90), gasLeft)
		})
	}
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

		err = mem.Write(uint32(ho), dataToHash)
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

		gasRemaining, regs, mem, err := host_call.Lookup(initialGas, initialRegs, mem, sa, serviceId, serviceState)
		require.NoError(t, err)

		actualValue := make([]byte, len(val))
		err = mem.Read(uint32(bo), actualValue)
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

	k, err := statekey.NewStorage(serviceId, keyData)
	require.NoError(t, err)

	sa := service.NewServiceAccount()

	err = sa.InsertStorage(k, uint64(len(keyData)), value)
	require.NoError(t, err)

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

	err = mem.Write(uint32(ko), keyData)
	require.NoError(t, err)

	gasRemaining, regs, mem, err := host_call.Read(initialGas, initialRegs, mem, sa, serviceId, serviceState)
	require.NoError(t, err)
	actualValue := make([]byte, len(value))
	err = mem.Read(uint32(bo), actualValue)
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

	k, err := statekey.NewStorage(serviceId, keyData)
	require.NoError(t, err)

	sa := service.NewServiceAccount()
	sa.Balance = 200

	ko := polkavm.RWAddressBase
	kz := uint32(len(keyData))

	vo := polkavm.RWAddressBase + 100
	vz := uint32(len(value))

	initialRegs[polkavm.A0] = uint64(ko)
	initialRegs[polkavm.A1] = uint64(kz)
	initialRegs[polkavm.A2] = uint64(vo)
	initialRegs[polkavm.A3] = uint64(vz)
	err = mem.Write(uint32(ko), keyData)
	require.NoError(t, err)
	err = mem.Write(uint32(vo), value)
	require.NoError(t, err)

	gasRemaining, regs, mem, updatedSa, err := host_call.Write(initialGas, initialRegs, mem, sa, serviceId)
	require.NoError(t, err)

	actualValue := make([]byte, len(value))
	err = mem.Read(uint32(vo), actualValue)
	require.NoError(t, err)
	require.Equal(t, value, actualValue)

	actualKey := make([]byte, len(keyData))
	err = mem.Read(uint32(ko), actualKey)
	require.NoError(t, err)
	require.Equal(t, keyData, actualKey)

	require.Equal(t, uint64(host_call.NONE), regs[polkavm.A0])
	require.NotNil(t, updatedSa)
	storedValue, keyExists := updatedSa.GetStorage(k)
	require.True(t, keyExists)
	require.Equal(t, value, storedValue)

	require.Equal(t, uint32(1), updatedSa.GetTotalNumberOfItems())
	require.Equal(t, 34+uint64(len(keyData))+uint64(len(value)), updatedSa.GetTotalNumberOfOctets())

	require.Equal(t, polkavm.Gas(90), gasRemaining)

	// Second call: Delete
	initialRegs[polkavm.A3] = 0 // vz = 0 → delete

	gasRemaining, _, mem, updatedSa, err = host_call.Write(gasRemaining, initialRegs, mem, updatedSa, serviceId)
	require.NoError(t, err)

	require.Equal(t, uint32(0), updatedSa.GetTotalNumberOfItems())
	require.Equal(t, uint64(0), updatedSa.GetTotalNumberOfOctets())
	_, ok := updatedSa.GetStorage(k)
	require.False(t, ok)
	require.Equal(t, polkavm.Gas(80), gasRemaining)
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
		CodeHash:                       crypto.Hash{0x01, 0x02, 0x03},
		Balance:                        1000,
		GasLimitForAccumulator:         5000,
		GasLimitOnTransfer:             2000,
		GratisStorageOffset:            10,
		CreationTimeslot:               jamtime.Timeslot(10),
		MostRecentAccumulationTimeslot: jamtime.Timeslot(10),
		ParentService:                  1,
	}

	serviceState := service.ServiceState{
		serviceId: sampleAccount,
	}

	// E(ac, E8(ab, at, ag, am, ao), E4(ai), E8(af), E4(ar, aa, ap)) = 96 bytes
	expectedByteLength := uint64(96)

	omega1 := polkavm.RWAddressBase
	initialRegs[polkavm.A0] = uint64(serviceId)
	initialRegs[polkavm.A1] = uint64(omega1)
	initialRegs[polkavm.A2] = 0
	initialRegs[polkavm.A3] = expectedByteLength

	gasRemaining, regs, mem, err := host_call.Info(initialGas, initialRegs, mem, serviceId, serviceState)
	require.NoError(t, err)

	require.Equal(t, expectedByteLength, regs[polkavm.A0])

	receivedAccountInfo := make([]byte, 32+6*8+4*4)
	err = mem.Read(uint32(omega1), receivedAccountInfo)
	require.NoError(t, err)

	thresholdBalance, err := sampleAccount.ThresholdBalance()
	require.NoError(t, err)
	expectedAccountInfo := slices.Concat(
		sampleAccount.CodeHash[:],
		jam.EncodeUint64(sampleAccount.Balance),
		jam.EncodeUint64(thresholdBalance),
		jam.EncodeUint64(sampleAccount.GasLimitForAccumulator),
		jam.EncodeUint64(sampleAccount.GasLimitOnTransfer),
		jam.EncodeUint64(sampleAccount.GetTotalNumberOfOctets()),
		jam.EncodeUint32(sampleAccount.GetTotalNumberOfItems()),
		jam.EncodeUint64(sampleAccount.GratisStorageOffset),
		jam.EncodeUint32(uint32(sampleAccount.CreationTimeslot)),
		jam.EncodeUint32(uint32(sampleAccount.MostRecentAccumulationTimeslot)),
		jam.EncodeUint32(uint32(sampleAccount.ParentService)),
	)

	require.Equal(t, expectedAccountInfo, receivedAccountInfo)

	require.Equal(t, polkavm.Gas(90), gasRemaining)
}
