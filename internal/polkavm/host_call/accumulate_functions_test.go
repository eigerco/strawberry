package host_call

import (
	"maps"
	"math"
	"slices"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/eigerco/strawberry/internal/block"
	"github.com/eigerco/strawberry/internal/common"
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/jamtime"
	. "github.com/eigerco/strawberry/internal/polkavm"
	"github.com/eigerco/strawberry/internal/polkavm/interpreter"
	pvmutil "github.com/eigerco/strawberry/internal/polkavm/util"
	"github.com/eigerco/strawberry/internal/safrole"
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
		ServiceAccount: nil,
		AuthorizationsQueue: state.PendingAuthorizersQueues{
			0: [state.PendingAuthorizersQueueSize]crypto.Hash(
				generate(t, testutils.RandomHash, state.PendingAuthorizersQueueSize),
			),
		},
		ValidatorKeys:      safrole.ValidatorsData(generate(t, testutils.RandomValidatorKey, common.NumberOfValidators)),
		ServiceID:          123,
		DeferredTransfers:  nil,
		ServicesState:      nil,
		PrivilegedServices: state.PrivilegedServices{},
	}
	var oldServiceID block.ServiceId = 123123
	var newServiceID = pvmutil.Check(pvmutil.Bump(oldServiceID), make(state.ServiceState))
	randomHash := testutils.RandomHash(t)

	tests := []struct {
		name        string
		alloc       alloc
		initialRegs deltaRegs
		initialGas  Gas
		fn          hostCall

		serviceId block.ServiceId
		timeslot  jamtime.Timeslot
		X         AccumulateContext
		Y         AccumulateContext

		expectedDeltaRegs deltaRegs
		expectedGas       Gas
		expectedX         AccumulateContext
		expectedY         AccumulateContext
		err               error
	}{
		{
			name: "empower",
			fn:   fnStd(Empower),
			alloc: alloc{
				A3: slices.Concat(
					encodeNumber(uint32(123)),
					encodeNumber(uint64(12341234)),
					encodeNumber(uint32(234)),
					encodeNumber(uint64(23452345)),
					encodeNumber(uint32(345)),
					encodeNumber(uint64(34563456)),
				),
			},
			initialRegs: deltaRegs{
				A0: 111,
				A1: 222,
				A2: 333,
				A4: 3,
			},
			expectedDeltaRegs: deltaRegs{
				A0: uint32(OK),
			},

			initialGas:  100,
			expectedGas: 88,
			expectedX: AccumulateContext{
				PrivilegedServices: state.PrivilegedServices{
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
				A0: uint32(OK),
			},
			expectedX: AccumulateContext{
				AuthorizationsQueue: state.PendingAuthorizersQueues{
					1: [state.PendingAuthorizersQueueSize]crypto.Hash(authHashes),
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
				A0: uint32(OK),
			},
			expectedX: AccumulateContext{
				ValidatorKeys: safrole.ValidatorsData(validatorKeys),
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
		}, {
			name: "new",
			fn:   fnStd(New),
			alloc: alloc{
				A0: hash2bytes(randomHash),
			},
			initialRegs: merge(
				deltaRegs{A1: 123123},
				storeUint64(123124123, A2, A3),
				storeUint64(756846353, A4, A5),
			),
			expectedDeltaRegs: deltaRegs{
				A0: uint32(newServiceID),
			},
			initialGas:  100,
			expectedGas: 88,
			X: AccumulateContext{
				ServiceID: oldServiceID,
				ServiceAccount: &state.ServiceAccount{
					Balance: 123123123,
				},
				ServicesState: state.ServiceState{},
			},
			expectedX: AccumulateContext{
				ServicesState: state.ServiceState{
					newServiceID: state.ServiceAccount{
						Storage: make(map[crypto.Hash][]byte),
						PreimageMeta: map[state.PreImageMetaKey]state.PreimageHistoricalTimeslots{
							{Hash: randomHash, Length: state.PreimageLength(123123)}: {},
						},
						CodeHash:               randomHash,
						GasLimitForAccumulator: 123124123,
						GasLimitOnTransfer:     756846353,
						Balance:                100, // balance of the new service
					},
				},
				ServiceID: pvmutil.Check(pvmutil.Bump(oldServiceID), make(state.ServiceState)),
				ServiceAccount: &state.ServiceAccount{
					Balance: 123123123 - 100, // initial balance minus balance of the new service
				},
			},
		}, {
			name: "upgrade",
			fn:   fnStd(Upgrade),
			alloc: alloc{
				A0: hash2bytes(randomHash),
			},
			initialRegs: merge(
				storeUint64(345345345345, A1, A2),
				storeUint64(456456456456, A3, A4),
			),
			expectedDeltaRegs: deltaRegs{
				A0: uint32(OK),
			},
			initialGas:  100,
			expectedGas: 88,
			X:           AccumulateContext{ServiceAccount: &state.ServiceAccount{}},
			expectedX: AccumulateContext{
				ServiceAccount: &state.ServiceAccount{
					CodeHash:               randomHash,
					GasLimitForAccumulator: 345345345345,
					GasLimitOnTransfer:     456456456456,
				},
			},
		}, {
			name: "transfer",
			fn:   fnSvc(Transfer),
			alloc: alloc{
				A5: fixedSizeBytes(state.TransferMemoSizeBytes, []byte("memo message")),
			},
			initialRegs: merge(
				deltaRegs{
					A0: 1234, // d: receiver
				},
				storeUint64(100000000000, A1, A2), // a
				storeUint64(80, A3, A4),           // g
			),
			expectedDeltaRegs: deltaRegs{
				A0: uint32(OK),
			},
			serviceId:   block.ServiceId(123123123),
			initialGas:  100000000100,
			expectedGas: 88,
			X: AccumulateContext{
				ServicesState: state.ServiceState{
					1234: {
						GasLimitOnTransfer: 1,
					},
				},
				ServiceAccount: &state.ServiceAccount{
					Balance: 100000000100,
				},
			},
			expectedX: AccumulateContext{
				ServicesState: state.ServiceState{
					1234: {
						GasLimitOnTransfer: 1,
					},
				},
				ServiceAccount: &state.ServiceAccount{
					Balance: 100000000100,
				},
				DeferredTransfers: []state.DeferredTransfer{{
					SenderServiceIndex:   block.ServiceId(123123123),
					ReceiverServiceIndex: 1234,
					Balance:              100000000000,
					Memo:                 state.Memo(fixedSizeBytes(state.TransferMemoSizeBytes, []byte("memo message"))),
					GasLimit:             80,
				}},
			},
		}, {
			name: "quit",
			fn:   fnSvc(Quit),
			alloc: alloc{
				A1: fixedSizeBytes(state.TransferMemoSizeBytes, []byte("memo message 2")),
			},
			initialRegs: deltaRegs{
				A0: 1234, // d: receiver address
			},
			expectedDeltaRegs: deltaRegs{
				A0: uint32(OK),
			},
			serviceId:   block.ServiceId(123123123),
			initialGas:  100,
			expectedGas: 88,
			X: AccumulateContext{
				ServicesState: state.ServiceState{
					1234: {
						GasLimitOnTransfer: 1,
					},
				},
				ServiceAccount: &state.ServiceAccount{
					Balance: 100,
				},
			},
			err: ErrHalt,
			expectedX: AccumulateContext{
				ServicesState: state.ServiceState{
					1234: {
						GasLimitOnTransfer: 1,
					},
				},
				ServiceAccount: &state.ServiceAccount{
					Balance: 100,
				},
				DeferredTransfers: []state.DeferredTransfer{{
					SenderServiceIndex:   block.ServiceId(123123123),
					ReceiverServiceIndex: 1234,
					Balance:              100,
					Memo:                 state.Memo(fixedSizeBytes(state.TransferMemoSizeBytes, []byte("memo message 2"))),
					GasLimit:             89,
				}},
			},
		}, {
			name: "solicit",
			fn:   fnTms(Solicit),
			alloc: alloc{
				A0: hash2bytes(randomHash),
			},
		}, {
			name: "forget",
			fn:   fnTms(Forget),
			alloc: alloc{
				A0: hash2bytes(randomHash),
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
				SP: memoryMap.StackAddressHigh,
			}
			stackAddress := memoryMap.StackAddressLow
			for addrReg, v := range tc.alloc {
				require.Greater(t, addrReg, S1)
				err = mem.Write(stackAddress, v)
				require.NoError(t, err)

				initialRegs[addrReg] = stackAddress
				stackAddress = stackAddress + uint32(len(v))
			}
			for i, v := range tc.initialRegs {
				initialRegs[i] = v
			}
			hostCall := func(hostCall uint32, gasCounter Gas, regs Registers, mem Memory, x AccumulateContextPair) (Gas, Registers, Memory, AccumulateContextPair, error) {
				gasCounter, regs, mem, x, err = tc.fn(gasCounter, regs, mem, x, tc.serviceId, make(state.ServiceState), tc.timeslot)
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
				expectedRegs[i] = reg
			}
			assert.Equal(t, expectedRegs, regs)
			assert.Equal(t, tc.expectedGas, gasRemaining)
			assert.Equal(t, tc.expectedX, ctxPair.RegularCtx)
			assert.Equal(t, tc.expectedY, ctxPair.ExceptionalCtx)
		})
	}
}

type hostCall func(Gas, Registers, Memory, AccumulateContextPair, block.ServiceId, state.ServiceState, jamtime.Timeslot) (Gas, Registers, Memory, AccumulateContextPair, error)
type alloc map[Reg][]byte
type deltaRegs map[Reg]uint32

func fixedSizeBytes(size int, b []byte) []byte {
	bb := make([]byte, size)
	copy(bb, b)
	return bb
}

func checkUint64(t *testing.T, gas uint64) deltaRegs {
	a0 := uint32(math.Mod(float64(gas), 1<<32))
	a1 := uint32(math.Floor(float64(gas) / (1 << 32)))
	assert.Equal(t, gas, uint64(a1)<<32|uint64(a0))
	return deltaRegs{
		A0: a0,
		A1: a1,
	}
}

func storeUint64(i uint64, reg1, reg2 Reg) deltaRegs {
	return deltaRegs{
		reg1: uint32(math.Mod(float64(i), 1<<32)),
		reg2: uint32(math.Floor(float64(i) / (1 << 32))),
	}
}

func merge[M ~map[K]V, K comparable, V any](dd ...M) M {
	result := make(M)
	for _, d := range dd {
		maps.Copy(result, d)
	}
	return result
}

func fnStd(fn func(Gas, Registers, Memory, AccumulateContextPair) (Gas, Registers, Memory, AccumulateContextPair, error)) hostCall {
	return func(gas Gas, regs Registers, mem Memory, ctxPair AccumulateContextPair, serviceIndex block.ServiceId, serviceState state.ServiceState, timeslot jamtime.Timeslot) (Gas, Registers, Memory, AccumulateContextPair, error) {
		return fn(gas, regs, mem, ctxPair)
	}
}

func fnSvc(fn func(Gas, Registers, Memory, AccumulateContextPair, block.ServiceId, state.ServiceState) (Gas, Registers, Memory, AccumulateContextPair, error)) hostCall {
	return func(gas Gas, regs Registers, mem Memory, ctxPair AccumulateContextPair, serviceIndex block.ServiceId, serviceState state.ServiceState, timeslot jamtime.Timeslot) (Gas, Registers, Memory, AccumulateContextPair, error) {
		return fn(gas, regs, mem, ctxPair, serviceIndex, serviceState)
	}
}

func fnTms(fn func(Gas, Registers, Memory, AccumulateContextPair, jamtime.Timeslot) (Gas, Registers, Memory, AccumulateContextPair, error)) hostCall {
	return func(gas Gas, regs Registers, mem Memory, ctxPair AccumulateContextPair, serviceIndex block.ServiceId, serviceState state.ServiceState, timeslot jamtime.Timeslot) (Gas, Registers, Memory, AccumulateContextPair, error) {
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

func encodeNumber[T ~uint8 | ~uint16 | ~uint32 | ~uint64](v T) []byte {
	return jam.SerializeTrivialNatural(v, uint8(unsafe.Sizeof(v)))
}