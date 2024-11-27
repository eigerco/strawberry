package host_call

import (
	"math"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/eigerco/strawberry/internal/block"
	"github.com/eigerco/strawberry/internal/common"
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/jamtime"
	. "github.com/eigerco/strawberry/internal/polkavm"
	"github.com/eigerco/strawberry/internal/polkavm/interpreter"
	"github.com/eigerco/strawberry/internal/safrole"
	"github.com/eigerco/strawberry/internal/service"
	"github.com/eigerco/strawberry/internal/state"
	"github.com/eigerco/strawberry/internal/testutils"
	"github.com/eigerco/strawberry/pkg/serialization/codec/jam"
)

func TestAccumulate(t *testing.T) {
	pp := &Program{
		RODataSize: 0,
		RWDataSize: 256,
		StackSize:  512,
		Instructions: []Instruction{
			{Opcode: Ecalli, Imm: []uint32{0}, Offset: 0, Length: 1},
			{Opcode: JumpIndirect, Imm: []uint32{0}, Reg: []Reg{RA}, Offset: 1, Length: 2},
		},
	}

	authHashes := generate(t, testutils.RandomHash, state.PendingAuthorizersQueueSize)
	validatorKeys := generate(t, testutils.RandomValidatorKey, common.NumberOfValidators)
	checkpointCtx := AccumulateContext{
		AccumulationState: state.AccumulationState{
			WorkReportsQueue: state.PendingAuthorizersQueues{
				0: [state.PendingAuthorizersQueueSize]crypto.Hash(
					generate(t, testutils.RandomHash, state.PendingAuthorizersQueueSize),
				),
			},
			ValidatorKeys:      safrole.ValidatorsData(generate(t, testutils.RandomValidatorKey, common.NumberOfValidators)),
			PrivilegedServices: service.PrivilegedServices{},
		},
		ServiceId: 123,
	}
	var currentServiceID block.ServiceId = 123123
	var newServiceID block.ServiceId = 123124
	randomHash := testutils.RandomHash(t)
	randomHash2 := testutils.RandomHash(t)
	randomTimeslot1 := testutils.RandomTimeslot()
	randomTimeslot2 := testutils.RandomTimeslot()
	randomTimeslot3 := testutils.RandomTimeslot()

	tests := []struct {
		name        string
		alloc       alloc
		initialRegs deltaRegs
		initialGas  uint64
		fn          hostCall

		timeslot jamtime.Timeslot
		X        AccumulateContext
		Y        AccumulateContext

		expectedDeltaRegs deltaRegs
		expectedGas       Gas
		expectedX         AccumulateContext
		expectedY         AccumulateContext
		err               error
	}{
		{
			name: "empower",
			fn:   fnStd(Bless),
			alloc: alloc{
				A3: slices.Concat(
					encodeNumber(t, uint32(123)),
					encodeNumber(t, uint64(12341234)),
					encodeNumber(t, uint32(234)),
					encodeNumber(t, uint64(23452345)),
					encodeNumber(t, uint32(345)),
					encodeNumber(t, uint64(34563456)),
				),
			},
			initialRegs: deltaRegs{
				A0: 111,
				A1: 222,
				A2: 333,
				A4: 3,
			},
			expectedDeltaRegs: deltaRegs{
				A0: uint64(OK),
			},

			initialGas:  100,
			expectedGas: 88,
			expectedX: AccumulateContext{
				AccumulationState: state.AccumulationState{
					PrivilegedServices: service.PrivilegedServices{
						ManagerServiceId:   111,
						AssignServiceId:    222,
						DesignateServiceId: 333,
						AmountOfGasPerServiceId: map[block.ServiceId]uint64{
							123: 12341234,
							234: 23452345,
							345: 34563456,
						},
					},
				},
			},
		}, {
			name: "assign",
			fn:   fnStd(Assign),
			alloc: alloc{
				A1: slices.Concat(transform(authHashes, hash2bytes)...),
			},
			initialRegs: deltaRegs{
				A0: 1, // core id
			},
			initialGas:  100,
			expectedGas: 88,
			expectedDeltaRegs: deltaRegs{
				A0: uint64(OK),
			},
			expectedX: AccumulateContext{
				AccumulationState: state.AccumulationState{
					WorkReportsQueue: state.PendingAuthorizersQueues{
						1: [state.PendingAuthorizersQueueSize]crypto.Hash(authHashes),
					},
				},
			},
		}, {
			name: "designate",
			fn:   fnStd(Designate),
			alloc: alloc{
				A0: slices.Concat(transform(validatorKeys, validatorKey2bytes)...),
			},
			initialRegs: deltaRegs{},
			initialGas:  100,
			expectedGas: 88,
			expectedDeltaRegs: deltaRegs{
				A0: uint64(OK),
			},
			expectedX: AccumulateContext{
				AccumulationState: state.AccumulationState{
					ValidatorKeys: safrole.ValidatorsData(validatorKeys),
				},
			},
		}, {
			name:              "checkpoint",
			fn:                fnStd(Checkpoint),
			X:                 checkpointCtx,
			initialGas:        100,
			expectedGas:       88,
			expectedDeltaRegs: checkUint64(t, 89),
			expectedX:         checkpointCtx,
			expectedY:         checkpointCtx,
		},
		{
			name: "new",
			fn:   fnStd(New),
			alloc: alloc{
				A0: hash2bytes(randomHash),
			},
			initialRegs: deltaRegs{A1: 123123, A2: 123124123, A3: 756846353},
			expectedDeltaRegs: deltaRegs{
				A0: uint64(currentServiceID),
			},
			initialGas:  100,
			expectedGas: 88,
			X: AccumulateContext{
				ServiceId:    currentServiceID,
				NewServiceId: newServiceID,
				ServiceState: service.ServiceState{
					currentServiceID: {
						Balance: 123123123,
					},
				},
				AccumulationState: state.AccumulationState{
					ServiceState: make(service.ServiceState),
				},
			},
			expectedX: AccumulateContext{
				AccumulationState: state.AccumulationState{
					ServiceState: service.ServiceState{
						service.CheckIndex(service.BumpIndex(newServiceID), make(service.ServiceState)): {
							Storage: make(map[crypto.Hash][]byte),
							PreimageMeta: map[service.PreImageMetaKey]service.PreimageHistoricalTimeslots{
								{Hash: randomHash, Length: service.PreimageLength(123123)}: {},
							},
							CodeHash:               randomHash,
							GasLimitForAccumulator: 123124123,
							GasLimitOnTransfer:     756846353,
							Balance:                100, // balance of the new service
						},
					},
				},
				NewServiceId: newServiceID,
				ServiceId:    service.CheckIndex(service.BumpIndex(newServiceID), make(service.ServiceState)),
				ServiceState: service.ServiceState{
					currentServiceID: {
						Balance: 123123123 - 100, // initial balance minus balance of the new service
					},
				},
			},
		},
		{
			name: "upgrade",
			fn:   fnStd(Upgrade),
			alloc: alloc{
				A0: hash2bytes(randomHash),
			},
			initialRegs: deltaRegs{A1: 3453453453, A2: 456456456},
			expectedDeltaRegs: deltaRegs{
				A0: uint64(OK),
			},
			initialGas:  100,
			expectedGas: 88,
			X: AccumulateContext{
				ServiceId:    currentServiceID,
				ServiceState: service.ServiceState{currentServiceID: {}},
			},
			expectedX: AccumulateContext{
				ServiceId: currentServiceID,
				ServiceState: service.ServiceState{currentServiceID: {
					CodeHash:               randomHash,
					GasLimitForAccumulator: 3453453453,
					GasLimitOnTransfer:     456456456,
				}},
			},
		}, {
			name: "transfer",
			fn:   fnStd(Transfer),
			alloc: alloc{
				A3: fixedSizeBytes(service.TransferMemoSizeBytes, []byte("memo message")),
			},
			initialRegs: deltaRegs{
				A0: 1234,       // d: receiver
				A1: 1000000000, // a
				A2: 80,         // g
			},
			expectedDeltaRegs: deltaRegs{
				A0: uint64(OK),
			},
			initialGas:  1000000100,
			expectedGas: 88,
			X: AccumulateContext{
				ServiceId: block.ServiceId(123123123),
				ServiceState: service.ServiceState{
					block.ServiceId(123123123): {
						Balance: 1000000100,
					},
				},
				AccumulationState: state.AccumulationState{
					ServiceState: service.ServiceState{
						1234: {
							GasLimitOnTransfer: 1,
						},
					},
				},
			},
			expectedX: AccumulateContext{
				AccumulationState: state.AccumulationState{
					ServiceState: service.ServiceState{
						1234: {
							GasLimitOnTransfer: 1,
						},
					},
				},
				ServiceId: block.ServiceId(123123123),
				ServiceState: service.ServiceState{
					block.ServiceId(123123123): {
						Balance: 1000000100,
					},
				},
				DeferredTransfers: []service.DeferredTransfer{{
					SenderServiceIndex:   block.ServiceId(123123123),
					ReceiverServiceIndex: 1234,
					Balance:              1000000000,
					Memo:                 service.Memo(fixedSizeBytes(service.TransferMemoSizeBytes, []byte("memo message"))),
					GasLimit:             80,
				}},
			},
		}, {
			name: "quit",
			fn:   fnStd(Quit),
			alloc: alloc{
				A1: fixedSizeBytes(service.TransferMemoSizeBytes, []byte("memo message 2")),
			},
			initialRegs: deltaRegs{
				A0: 1234, // d: receiver address
			},
			expectedDeltaRegs: deltaRegs{
				A0: uint64(OK),
			},
			initialGas:  100,
			expectedGas: 88,
			X: AccumulateContext{
				ServiceId: block.ServiceId(123123123),
				ServiceState: service.ServiceState{
					block.ServiceId(123123123): {
						Balance: 100,
					},
				},
				AccumulationState: state.AccumulationState{
					ServiceState: service.ServiceState{
						1234: {
							GasLimitOnTransfer: 1,
						},
					},
				},
			},
			err: ErrHalt,
			expectedX: AccumulateContext{
				AccumulationState: state.AccumulationState{
					ServiceState: service.ServiceState{
						1234: {
							GasLimitOnTransfer: 1,
						},
					},
				},
				ServiceId: block.ServiceId(123123123),
				ServiceState: service.ServiceState{
					block.ServiceId(123123123): {
						Balance: 100,
					},
				},
				DeferredTransfers: []service.DeferredTransfer{{
					SenderServiceIndex:   block.ServiceId(123123123),
					ReceiverServiceIndex: 1234,
					Balance:              100,
					Memo:                 service.Memo(fixedSizeBytes(service.TransferMemoSizeBytes, []byte("memo message 2"))),
					GasLimit:             89,
				}},
			},
		}, {
			name: "solicit_out_of_gas",
			fn:   fnTms(Solicit),
			alloc: alloc{
				A0: hash2bytes(randomHash),
			},
			initialRegs: deltaRegs{
				A1: 256, // z: preimage length
			},
			timeslot:   jamtime.Timeslot(1000),
			initialGas: 10, // Less than SolicitCost
			X: AccumulateContext{
				ServiceId: currentServiceID,
				ServiceState: service.ServiceState{
					currentServiceID: {
						Balance:      200,
						PreimageMeta: map[service.PreImageMetaKey]service.PreimageHistoricalTimeslots{},
					},
				},
			},
			expectedGas: 8, // Gas gets decremented by fixed amount (2) when processing instructions even on error
			expectedX: AccumulateContext{
				ServiceId: currentServiceID,
				ServiceState: service.ServiceState{
					currentServiceID: {
						Balance:      200,
						PreimageMeta: map[service.PreImageMetaKey]service.PreimageHistoricalTimeslots{},
					},
				},
			},
			err: ErrOutOfGas,
		}, {
			name: "solicit_new_preimage",
			fn:   fnTms(Solicit),
			alloc: alloc{
				A0: hash2bytes(randomHash),
			},
			initialRegs: deltaRegs{
				A1: 256, // z: preimage length
			},
			timeslot:    jamtime.Timeslot(1000),
			initialGas:  100,
			expectedGas: 88,
			expectedDeltaRegs: deltaRegs{
				A0: uint64(OK),
			},
			X: AccumulateContext{
				ServiceId: currentServiceID,
				ServiceState: service.ServiceState{
					currentServiceID: {
						Balance:      200,
						PreimageMeta: make(map[service.PreImageMetaKey]service.PreimageHistoricalTimeslots),
					},
				},
			},
			expectedX: AccumulateContext{
				ServiceId: currentServiceID,
				ServiceState: service.ServiceState{
					currentServiceID: {
						Balance: 200,
						PreimageMeta: map[service.PreImageMetaKey]service.PreimageHistoricalTimeslots{
							{Hash: randomHash, Length: service.PreimageLength(256)}: {},
						},
					},
				},
			},
		}, {
			name: "solicit_append_timeslot",
			fn:   fnTms(Solicit),
			alloc: alloc{
				A0: hash2bytes(randomHash),
			},
			initialRegs: deltaRegs{
				A1: 256, // z: preimage length
			},
			timeslot:    jamtime.Timeslot(1000),
			initialGas:  100,
			expectedGas: 88,
			expectedDeltaRegs: deltaRegs{
				A0: uint64(OK),
			},
			X: AccumulateContext{
				ServiceId: currentServiceID,
				ServiceState: service.ServiceState{
					currentServiceID: {
						Balance: 200,
						PreimageMeta: map[service.PreImageMetaKey]service.PreimageHistoricalTimeslots{
							{Hash: randomHash, Length: service.PreimageLength(256)}: {800, 900}, // Exactly 2 timeslots
						},
					},
				},
			},
			expectedX: AccumulateContext{
				ServiceId: currentServiceID,
				ServiceState: service.ServiceState{
					currentServiceID: {
						Balance: 200,
						PreimageMeta: map[service.PreImageMetaKey]service.PreimageHistoricalTimeslots{
							{Hash: randomHash, Length: service.PreimageLength(256)}: {800, 900, 1000}, // Appended current timeslot
						},
					},
				},
			},
		}, {
			name: "solicit_invalid_timeslots",
			fn:   fnTms(Solicit),
			alloc: alloc{
				A0: hash2bytes(randomHash),
			},
			initialRegs: deltaRegs{
				A1: 256,
			},
			timeslot:    jamtime.Timeslot(1000),
			initialGas:  100,
			expectedGas: 88,
			expectedDeltaRegs: deltaRegs{
				A0: uint64(HUH),
			},
			X: AccumulateContext{
				ServiceId: currentServiceID,
				ServiceState: service.ServiceState{
					currentServiceID: {
						Balance: 200,
						PreimageMeta: map[service.PreImageMetaKey]service.PreimageHistoricalTimeslots{
							{Hash: randomHash, Length: service.PreimageLength(256)}: {800}, // Invalid: not 2 timeslots
						},
					},
				},
			},
			expectedX: AccumulateContext{
				ServiceId: currentServiceID,
				ServiceState: service.ServiceState{
					currentServiceID: {
						Balance: 200,
						PreimageMeta: map[service.PreImageMetaKey]service.PreimageHistoricalTimeslots{
							{Hash: randomHash, Length: service.PreimageLength(256)}: {800}, // State unchanged
						},
					},
				},
			},
		}, {
			name: "solicit_insufficient_balance",
			fn:   fnTms(Solicit),
			alloc: alloc{
				A0: hash2bytes(randomHash),
			},
			initialRegs: deltaRegs{
				A1: 256,
			},
			timeslot:    jamtime.Timeslot(1000),
			initialGas:  100,
			expectedGas: 88,
			expectedDeltaRegs: deltaRegs{
				A0: uint64(FULL),
			},
			X: AccumulateContext{
				ServiceId: currentServiceID,
				ServiceState: service.ServiceState{
					currentServiceID: {
						Balance:      50, // Less than threshold
						PreimageMeta: map[service.PreImageMetaKey]service.PreimageHistoricalTimeslots{},
					},
				},
			},
			expectedX: AccumulateContext{
				ServiceId: currentServiceID,
				ServiceState: service.ServiceState{
					currentServiceID: {
						Balance: 50,
						PreimageMeta: map[service.PreImageMetaKey]service.PreimageHistoricalTimeslots{
							{Hash: randomHash, Length: service.PreimageLength(256)}: {},
						},
					},
				},
			},
		}, {
			name:              "forget_0",
			fn:                fnTms(Forget),
			alloc:             alloc{A0: hash2bytes(randomHash)},
			initialRegs:       deltaRegs{A1: 123},
			expectedDeltaRegs: deltaRegs{A0: uint64(OK)},
			initialGas:        100,
			expectedGas:       88,
			X: AccumulateContext{
				ServiceId: currentServiceID,
				ServiceState: service.ServiceState{
					currentServiceID: {
						PreimageMeta: map[service.PreImageMetaKey]service.PreimageHistoricalTimeslots{
							{Hash: randomHash, Length: 123}: {},
						},
						PreimageLookup: map[crypto.Hash][]byte{randomHash: {1, 2, 3, 4, 5, 6, 7}},
						CodeHash:       randomHash2,
						Balance:        111,
					},
				},
			},
			expectedX: AccumulateContext{
				ServiceId: currentServiceID,
				ServiceState: service.ServiceState{
					currentServiceID: {
						PreimageMeta:   map[service.PreImageMetaKey]service.PreimageHistoricalTimeslots{},
						PreimageLookup: map[crypto.Hash][]byte{},
						CodeHash:       randomHash2,
						Balance:        111,
					},
				},
			},
		}, {
			name:              "forget_1",
			fn:                fnTms(Forget),
			alloc:             alloc{A0: hash2bytes(randomHash)},
			initialRegs:       deltaRegs{A1: 123},
			expectedDeltaRegs: deltaRegs{A0: uint64(OK)},
			initialGas:        100,
			expectedGas:       88,
			timeslot:          randomTimeslot2,
			X: AccumulateContext{
				ServiceId: currentServiceID,
				ServiceState: service.ServiceState{
					currentServiceID: {
						PreimageMeta: map[service.PreImageMetaKey]service.PreimageHistoricalTimeslots{
							{Hash: randomHash, Length: 123}: {randomTimeslot1},
						},
						PreimageLookup: map[crypto.Hash][]byte{randomHash: {1, 2, 3, 4, 5, 6, 7}},
						CodeHash:       randomHash2,
						Balance:        111,
					},
				},
			},
			expectedX: AccumulateContext{
				ServiceId: currentServiceID,
				ServiceState: service.ServiceState{
					currentServiceID: {
						PreimageMeta: map[service.PreImageMetaKey]service.PreimageHistoricalTimeslots{
							{Hash: randomHash, Length: 123}: {randomTimeslot1, randomTimeslot2},
						},
						PreimageLookup: map[crypto.Hash][]byte{randomHash: {1, 2, 3, 4, 5, 6, 7}},
						CodeHash:       randomHash2,
						Balance:        111,
					},
				},
			},
		}, {
			name:              "forget_2",
			fn:                fnTms(Forget),
			alloc:             alloc{A0: hash2bytes(randomHash)},
			initialRegs:       deltaRegs{A1: 123},
			expectedDeltaRegs: deltaRegs{A0: uint64(OK)},
			initialGas:        100,
			expectedGas:       88,
			timeslot:          randomTimeslot2 + jamtime.PreimageExpulsionPeriod + 1,
			X: AccumulateContext{
				ServiceId: currentServiceID,
				ServiceState: service.ServiceState{
					currentServiceID: {
						PreimageMeta: map[service.PreImageMetaKey]service.PreimageHistoricalTimeslots{
							{Hash: randomHash, Length: 123}: {randomTimeslot1, randomTimeslot2},
						},
						PreimageLookup: map[crypto.Hash][]byte{randomHash: {1, 2, 3, 4, 5, 6, 7}},
						CodeHash:       randomHash2,
						Balance:        111,
					},
				},
			},
			expectedX: AccumulateContext{
				ServiceId: currentServiceID,
				ServiceState: service.ServiceState{
					currentServiceID: {
						PreimageMeta:   map[service.PreImageMetaKey]service.PreimageHistoricalTimeslots{},
						PreimageLookup: map[crypto.Hash][]byte{},
						CodeHash:       randomHash2,
						Balance:        111,
					},
				},
			},
		}, {
			name:              "forget_3",
			fn:                fnTms(Forget),
			alloc:             alloc{A0: hash2bytes(randomHash)},
			initialRegs:       deltaRegs{A1: 123},
			expectedDeltaRegs: deltaRegs{A0: uint64(OK)},
			initialGas:        100,
			expectedGas:       88,
			timeslot:          randomTimeslot2 + jamtime.PreimageExpulsionPeriod + 1,
			X: AccumulateContext{
				ServiceId: currentServiceID,
				ServiceState: service.ServiceState{
					currentServiceID: {
						PreimageMeta: map[service.PreImageMetaKey]service.PreimageHistoricalTimeslots{
							{Hash: randomHash, Length: 123}: {randomTimeslot1, randomTimeslot2, randomTimeslot3},
						},
						PreimageLookup: map[crypto.Hash][]byte{randomHash: {1, 2, 3, 4, 5, 6, 7}},
						CodeHash:       randomHash2,
						Balance:        111,
					},
				},
			},
			expectedX: AccumulateContext{
				ServiceId: currentServiceID,
				ServiceState: service.ServiceState{
					currentServiceID: {
						PreimageMeta: map[service.PreImageMetaKey]service.PreimageHistoricalTimeslots{
							{Hash: randomHash, Length: 123}: {randomTimeslot3, randomTimeslot2 + jamtime.PreimageExpulsionPeriod + 1},
						},
						PreimageLookup: map[crypto.Hash][]byte{randomHash: {1, 2, 3, 4, 5, 6, 7}},
						CodeHash:       randomHash2,
						Balance:        111,
					},
				},
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			memoryMap, err := NewMemoryMap(VmMinPageSize, 0, 0, 1<<19, 0)
			require.NoError(t, err)

			mem := memoryMap.NewMemory(nil, nil, nil)
			initialRegs := Registers{
				RA: VmAddressReturnToHost,
				SP: uint64(memoryMap.StackAddressHigh),
			}
			stackAddress := memoryMap.StackAddressLow
			for addrReg, v := range tc.alloc {
				require.Greater(t, addrReg, S1)
				err = mem.Write(stackAddress, v)
				require.NoError(t, err)

				initialRegs[addrReg] = uint64(stackAddress)
				stackAddress = stackAddress + uint32(len(v))
			}
			for i, v := range tc.initialRegs {
				initialRegs[i] = v
			}
			hostCall := func(hostCall uint32, gasCounter Gas, regs Registers, mem Memory, x AccumulateContextPair) (Gas, Registers, Memory, AccumulateContextPair, error) {
				gasCounter, regs, mem, x, err = tc.fn(gasCounter, regs, mem, x, tc.timeslot)
				require.ErrorIs(t, err, tc.err)
				return gasCounter, regs, mem, x, nil
			}
			gasRemaining, regs, _, ctxPair, err := interpreter.InvokeHostCall(
				pp, memoryMap,
				0, tc.initialGas, initialRegs, mem,
				hostCall, AccumulateContextPair{
					RegularCtx:     tc.X,
					ExceptionalCtx: tc.Y,
				})
			require.ErrorIs(t, err, ErrHalt)

			expectedRegs := initialRegs
			for i, reg := range tc.expectedDeltaRegs {
				expectedRegs[i] = uint64(reg)
			}
			assert.Equal(t, expectedRegs, regs)
			assert.Equal(t, tc.expectedGas, gasRemaining)
			assert.Equal(t, tc.expectedX, ctxPair.RegularCtx)
			assert.Equal(t, tc.expectedY, ctxPair.ExceptionalCtx)
		})
	}
}

type hostCall func(Gas, Registers, Memory, AccumulateContextPair, jamtime.Timeslot) (Gas, Registers, Memory, AccumulateContextPair, error)
type alloc map[Reg][]byte
type deltaRegs map[Reg]uint64

func fixedSizeBytes(size int, b []byte) []byte {
	bb := make([]byte, size)
	copy(bb, b)
	return bb
}

func checkUint64(t *testing.T, gas uint64) deltaRegs {
	a0 := uint64(math.Mod(float64(gas), 1<<32))
	a1 := uint64(math.Floor(float64(gas) / (1 << 32)))
	assert.Equal(t, gas, uint64(a1)<<32|uint64(a0))
	return deltaRegs{
		A0: a0,
		A1: a1,
	}
}

func fnStd(fn func(Gas, Registers, Memory, AccumulateContextPair) (Gas, Registers, Memory, AccumulateContextPair, error)) hostCall {
	return func(gas Gas, regs Registers, mem Memory, ctxPair AccumulateContextPair, timeslot jamtime.Timeslot) (Gas, Registers, Memory, AccumulateContextPair, error) {
		return fn(gas, regs, mem, ctxPair)
	}
}

func fnTms(fn func(Gas, Registers, Memory, AccumulateContextPair, jamtime.Timeslot) (Gas, Registers, Memory, AccumulateContextPair, error)) hostCall {
	return func(gas Gas, regs Registers, mem Memory, ctxPair AccumulateContextPair, timeslot jamtime.Timeslot) (Gas, Registers, Memory, AccumulateContextPair, error) {
		return fn(gas, regs, mem, ctxPair, timeslot)
	}
}

func generate[S any](t *testing.T, fn func(t *testing.T) S, n int) (slice []S) {
	slice = make([]S, n)
	for i := range n {
		slice[i] = fn(t)
	}
	return slice
}

func hash2bytes(s crypto.Hash) []byte {
	return s[:]
}

func validatorKey2bytes(v crypto.ValidatorKey) []byte {
	return slices.Concat(v.Bandersnatch[:], v.Ed25519, v.Bls[:], v.Metadata[:])
}

func transform[S, S2 any](slice1 []S, fn func(S) S2) (slice []S2) {
	slice = make([]S2, len(slice1))
	for i := range slice1 {
		slice[i] = fn(slice1[i])
	}
	return slice
}

func encodeNumber[T ~uint8 | ~uint16 | ~uint32 | ~uint64](t *testing.T, v T) []byte {
	res, err := jam.Marshal(v)
	require.NoError(t, err)
	return res
}
