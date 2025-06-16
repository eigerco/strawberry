package host_call

import (
	"fmt"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/eigerco/strawberry/internal/block"
	"github.com/eigerco/strawberry/internal/common"
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/jamtime"
	. "github.com/eigerco/strawberry/internal/polkavm"
	"github.com/eigerco/strawberry/internal/safrole"
	"github.com/eigerco/strawberry/internal/service"
	"github.com/eigerco/strawberry/internal/state"
	"github.com/eigerco/strawberry/internal/testutils"
	"github.com/eigerco/strawberry/pkg/serialization/codec/jam"
)

func TestAccumulate(t *testing.T) {
	pp := &Program{
		ProgramMemorySizes: ProgramMemorySizes{
			RODataSize:       0,
			RWDataSize:       256,
			StackSize:        512,
			InitialHeapPages: 200,
		},
	}

	authHashes := generate(t, testutils.RandomHash, state.PendingAuthorizersQueueSize)
	validatorKeys := generate(t, testutils.RandomValidatorKey, common.NumberOfValidators)
	checkpointCtx := AccumulateContext{
		AccumulationState: state.AccumulationState{
			PendingAuthorizersQueues: state.PendingAuthorizersQueues{
				0: [state.PendingAuthorizersQueueSize]crypto.Hash(
					generate(t, testutils.RandomHash, state.PendingAuthorizersQueueSize),
				),
			},
			ValidatorKeys: safrole.ValidatorsData(generate(t, testutils.RandomValidatorKey, common.NumberOfValidators)),
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

		extraParam any
		X          AccumulateContext
		Y          AccumulateContext

		expectedDeltaRegs deltaRegs
		expectedGas       Gas
		expectedX         AccumulateContext
		expectedY         AccumulateContext
		err               error
	}{
		{
			name: "bless",
			fn:   fnStd(Bless),
			alloc: alloc{
				A1: make([]byte, uint32(4*common.TotalNumberOfCores)),
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
				A2: 333,
				A4: 3,
			},
			expectedDeltaRegs: deltaRegs{
				A0: uint64(OK),
			},

			initialGas:  100,
			expectedGas: 90,
			expectedX: AccumulateContext{
				AccumulationState: state.AccumulationState{
					ManagerServiceId:   111,
					AssignedServiceIds: [common.TotalNumberOfCores]block.ServiceId{},
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
			expectedGas: 90,
			expectedDeltaRegs: deltaRegs{
				A0: uint64(OK),
			},
			expectedX: AccumulateContext{
				AccumulationState: state.AccumulationState{
					PendingAuthorizersQueues: state.PendingAuthorizersQueues{
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
			expectedGas: 90,
			expectedDeltaRegs: deltaRegs{
				A0: uint64(OK),
			},
			expectedX: AccumulateContext{
				AccumulationState: state.AccumulationState{
					ValidatorKeys: safrole.ValidatorsData(validatorKeys),
				},
			},
		}, {
			name:        "checkpoint",
			fn:          fnStd(Checkpoint),
			X:           checkpointCtx,
			initialGas:  100,
			expectedGas: 90,
			expectedDeltaRegs: deltaRegs{
				A0: uint64(90),
			},
			expectedX: checkpointCtx,
			expectedY: checkpointCtx,
		},
		{
			name: "new",
			fn:   fnStd(New),
			alloc: alloc{
				A0: hash2bytes(randomHash),
			},
			initialRegs: deltaRegs{A1: 100, A2: 100, A3: 100},
			expectedDeltaRegs: deltaRegs{
				A0: uint64(newServiceID),
			},
			initialGas:  100,
			expectedGas: 90,
			X: AccumulateContext{
				ServiceId:    currentServiceID,
				NewServiceId: newServiceID,
				AccumulationState: state.AccumulationState{
					ServiceState: service.ServiceState{
						currentServiceID: {
							Balance: 500,
						},
					},
				},
			},
			expectedX: AccumulateContext{
				AccumulationState: state.AccumulationState{
					ServiceState: service.ServiceState{
						service.CheckIndex(service.BumpIndex(newServiceID), make(service.ServiceState)): {
							Storage: service.NewAccountStorage(),
							PreimageMeta: map[service.PreImageMetaKey]service.PreimageHistoricalTimeslots{
								{Hash: randomHash, Length: service.PreimageLength(100)}: {},
							},
							CodeHash:               randomHash,
							GasLimitForAccumulator: 100,
							GasLimitOnTransfer:     100,
							Balance:                service.BasicMinimumBalance + service.AdditionalMinimumBalancePerItem*2 + service.AdditionalMinimumBalancePerOctet*(100+81), // =301 balance of the new service
						},
						currentServiceID: {
							Balance: 500 - 301, // initial balance minus balance of the new service
						},
					},
				},
				NewServiceId: service.CheckIndex(service.BumpIndex(newServiceID), make(service.ServiceState)),
				ServiceId:    currentServiceID,
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
			expectedGas: 90,
			X: AccumulateContext{
				ServiceId: currentServiceID,
				AccumulationState: state.AccumulationState{
					ServiceState: service.ServiceState{currentServiceID: {}},
				},
			},
			expectedX: AccumulateContext{
				ServiceId: currentServiceID,
				AccumulationState: state.AccumulationState{
					ServiceState: service.ServiceState{currentServiceID: {
						CodeHash:               randomHash,
						GasLimitForAccumulator: 3453453453,
						GasLimitOnTransfer:     456456456,
					}},
				},
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
			initialGas:  100,
			expectedGas: 10,
			X: AccumulateContext{
				ServiceId: block.ServiceId(123123123),
				AccumulationState: state.AccumulationState{
					ServiceState: service.ServiceState{
						1234: {
							GasLimitOnTransfer: 1,
						},
						block.ServiceId(123123123): {
							Balance: 1000000100,
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
						block.ServiceId(123123123): {
							Balance: 1000000100,
						},
					},
				},
				ServiceId: block.ServiceId(123123123),
				DeferredTransfers: []service.DeferredTransfer{{
					SenderServiceIndex:   block.ServiceId(123123123),
					ReceiverServiceIndex: 1234,
					Balance:              1000000000,
					Memo:                 service.Memo(fixedSizeBytes(service.TransferMemoSizeBytes, []byte("memo message"))),
					GasLimit:             80,
				}},
			},
		},
		{
			name:       "eject",
			fn:         fnWithExtra[jamtime.Timeslot](Eject),
			initialGas: 100,
			extraParam: jamtime.Timeslot(200),
			initialRegs: deltaRegs{
				A0: 999,
			},
			alloc: alloc{
				A1: hash2bytes(randomHash),
			},
			X: AccumulateContext{
				ServiceId: 222,
				AccumulationState: state.AccumulationState{
					ServiceState: service.ServiceState{
						// d = 999 (the ejected service)
						999: func() service.ServiceAccount {
							e32, err := jam.Marshal(struct {
								ServiceId block.ServiceId `jam:"length=32"`
							}{222})
							require.NoError(t, err)

							var codeHash crypto.Hash
							copy(codeHash[:], e32)

							preImgLookup := map[crypto.Hash][]byte{
								codeHash: make([]byte, 81),
							}

							preImgMeta := map[service.PreImageMetaKey]service.PreimageHistoricalTimeslots{
								{Hash: randomHash, Length: 0}: {50, 100},
							}

							return service.ServiceAccount{
								CodeHash:       codeHash,
								Balance:        100, // d_b
								PreimageLookup: preImgLookup,
								PreimageMeta:   preImgMeta,
							}
						}(),
						// x_s
						222: {
							Balance: 1000,
						},
					},
				},
			},
			expectedGas: 90,
			expectedDeltaRegs: deltaRegs{
				A0: uint64(OK),
			},
			// After success:
			//   - The ejected service 999 is removed
			//   - x_s(222).Balance = 1000+100=1100
			expectedX: AccumulateContext{
				ServiceId: 222,
				AccumulationState: state.AccumulationState{
					ServiceState: service.ServiceState{
						222: {
							Balance: 1100,
						},
					},
				},
			},
		},
		{
			name:       "query_empty_timeslots",
			fn:         fnStd(Query),
			initialGas: 100,
			initialRegs: deltaRegs{
				A1: 123,
			},
			alloc: alloc{
				A0: hash2bytes(randomHash),
			},
			X: AccumulateContext{
				ServiceId: 999,
				AccumulationState: state.AccumulationState{
					ServiceState: service.ServiceState{
						999: {
							PreimageMeta: map[service.PreImageMetaKey]service.PreimageHistoricalTimeslots{
								{
									Hash:   randomHash,
									Length: 123,
								}: {},
							},
						},
					},
				},
			},
			expectedDeltaRegs: deltaRegs{
				A0: 0,
				A1: 0,
			},
			expectedGas: 90,
			expectedX: AccumulateContext{
				ServiceId: 999,
				AccumulationState: state.AccumulationState{
					ServiceState: service.ServiceState{
						999: {
							PreimageMeta: map[service.PreImageMetaKey]service.PreimageHistoricalTimeslots{
								{Hash: randomHash, Length: 123}: {},
							},
						},
					},
				},
			},
		},
		{
			name:       "query_1timeslot",
			fn:         fnStd(Query),
			initialGas: 100,
			initialRegs: deltaRegs{
				A1: 123,
			},
			alloc: alloc{
				A0: hash2bytes(randomHash),
			},
			X: AccumulateContext{
				ServiceId: 999,
				AccumulationState: state.AccumulationState{
					ServiceState: service.ServiceState{
						999: {
							PreimageMeta: map[service.PreImageMetaKey]service.PreimageHistoricalTimeslots{
								{
									Hash:   randomHash,
									Length: 123,
								}: {11},
							},
						},
					},
				},
			},
			expectedDeltaRegs: deltaRegs{
				A0: 1 + (uint64(11) << 32),
				A1: 0,
			},
			expectedGas: 90,
			expectedX: AccumulateContext{
				ServiceId: 999,
				AccumulationState: state.AccumulationState{
					ServiceState: service.ServiceState{
						999: {
							PreimageMeta: map[service.PreImageMetaKey]service.PreimageHistoricalTimeslots{
								{Hash: randomHash, Length: 123}: {11},
							},
						},
					},
				},
			},
		},
		{
			name:       "query_2timeslots",
			fn:         fnStd(Query),
			initialGas: 100,
			initialRegs: deltaRegs{
				A1: 123,
			},
			alloc: alloc{
				A0: hash2bytes(randomHash),
			},
			X: AccumulateContext{
				ServiceId: 999,
				AccumulationState: state.AccumulationState{
					ServiceState: service.ServiceState{
						999: {
							PreimageMeta: map[service.PreImageMetaKey]service.PreimageHistoricalTimeslots{
								{
									Hash:   randomHash,
									Length: 123,
								}: {11, 12},
							},
						},
					},
				},
			},
			expectedDeltaRegs: deltaRegs{
				A0: 2 + (uint64(11) << 32),
				A1: uint64(12),
			},
			expectedGas: 90,
			expectedX: AccumulateContext{
				ServiceId: 999,
				AccumulationState: state.AccumulationState{
					ServiceState: service.ServiceState{
						999: {
							PreimageMeta: map[service.PreImageMetaKey]service.PreimageHistoricalTimeslots{
								{Hash: randomHash, Length: 123}: {11, 12},
							},
						},
					},
				},
			},
		},
		{
			name:       "query_3timeslots",
			fn:         fnStd(Query),
			initialGas: 100,
			initialRegs: deltaRegs{
				A1: 123,
			},
			alloc: alloc{
				A0: hash2bytes(randomHash),
			},
			X: AccumulateContext{
				ServiceId: 999,
				AccumulationState: state.AccumulationState{
					ServiceState: service.ServiceState{
						999: {
							PreimageMeta: map[service.PreImageMetaKey]service.PreimageHistoricalTimeslots{
								{
									Hash:   randomHash,
									Length: 123,
								}: {11, 12, 13},
							},
						},
					},
				},
			},
			expectedDeltaRegs: deltaRegs{
				A0: 3 + (uint64(11) << 32),
				A1: uint64(12) + (uint64(13) << 32),
			},
			expectedGas: 90,
			expectedX: AccumulateContext{
				ServiceId: 999,
				AccumulationState: state.AccumulationState{
					ServiceState: service.ServiceState{
						999: {
							PreimageMeta: map[service.PreImageMetaKey]service.PreimageHistoricalTimeslots{
								{Hash: randomHash, Length: 123}: {11, 12, 13},
							},
						},
					},
				},
			},
		},
		{
			name: "solicit_out_of_gas",
			fn:   fnWithExtra[jamtime.Timeslot](Solicit),
			alloc: alloc{
				A0: hash2bytes(randomHash),
			},
			initialRegs: deltaRegs{
				A1: 256, // z: preimage length
			},
			extraParam: jamtime.Timeslot(1000),
			initialGas: 9, // Less than SolicitCost
			X: AccumulateContext{
				ServiceId: currentServiceID,
				AccumulationState: state.AccumulationState{
					ServiceState: service.ServiceState{
						currentServiceID: {
							Balance:      200,
							PreimageMeta: map[service.PreImageMetaKey]service.PreimageHistoricalTimeslots{},
						},
					},
				},
			},
			expectedGas: 9,
			expectedX: AccumulateContext{
				ServiceId: currentServiceID,
				AccumulationState: state.AccumulationState{
					ServiceState: service.ServiceState{
						currentServiceID: {
							Balance:      200,
							PreimageMeta: map[service.PreImageMetaKey]service.PreimageHistoricalTimeslots{},
						},
					},
				},
			},
			err: ErrOutOfGas,
		}, {
			name: "solicit_new_preimage",
			fn:   fnWithExtra[jamtime.Timeslot](Solicit),
			alloc: alloc{
				A0: hash2bytes(randomHash),
			},
			initialRegs: deltaRegs{
				A1: 256, // z: preimage length
			},
			extraParam:  jamtime.Timeslot(1000),
			initialGas:  100,
			expectedGas: 90,
			expectedDeltaRegs: deltaRegs{
				A0: uint64(OK),
			},
			X: AccumulateContext{
				ServiceId: currentServiceID,
				AccumulationState: state.AccumulationState{
					ServiceState: service.ServiceState{
						currentServiceID: {
							Balance:      500,
							PreimageMeta: make(map[service.PreImageMetaKey]service.PreimageHistoricalTimeslots),
						},
					},
				},
			},
			expectedX: AccumulateContext{
				ServiceId: currentServiceID,
				AccumulationState: state.AccumulationState{
					ServiceState: service.ServiceState{
						currentServiceID: {
							Balance: 500,
							PreimageMeta: map[service.PreImageMetaKey]service.PreimageHistoricalTimeslots{
								{Hash: randomHash, Length: service.PreimageLength(256)}: {},
							},
						},
					},
				},
			},
		}, {
			name: "solicit_append_timeslot",
			fn:   fnWithExtra[jamtime.Timeslot](Solicit),
			alloc: alloc{
				A0: hash2bytes(randomHash),
			},
			initialRegs: deltaRegs{
				A1: 256, // z: preimage length
			},
			extraParam:  jamtime.Timeslot(1000),
			initialGas:  100,
			expectedGas: 90,
			expectedDeltaRegs: deltaRegs{
				A0: uint64(OK),
			},
			X: AccumulateContext{
				ServiceId: currentServiceID,
				AccumulationState: state.AccumulationState{
					ServiceState: service.ServiceState{
						currentServiceID: {
							Balance: 500,
							PreimageMeta: map[service.PreImageMetaKey]service.PreimageHistoricalTimeslots{
								{Hash: randomHash, Length: service.PreimageLength(256)}: {800, 900}, // Exactly 2 timeslots
							},
						},
					},
				},
			},
			expectedX: AccumulateContext{
				ServiceId: currentServiceID,
				AccumulationState: state.AccumulationState{
					ServiceState: service.ServiceState{
						currentServiceID: {
							Balance: 500,
							PreimageMeta: map[service.PreImageMetaKey]service.PreimageHistoricalTimeslots{
								{Hash: randomHash, Length: service.PreimageLength(256)}: {800, 900, 1000}, // Appended current timeslot
							},
						},
					},
				},
			},
		}, {
			name: "solicit_invalid_timeslots",
			fn:   fnWithExtra[jamtime.Timeslot](Solicit),
			alloc: alloc{
				A0: hash2bytes(randomHash),
			},
			initialRegs: deltaRegs{
				A1: 256,
			},
			extraParam:  jamtime.Timeslot(1000),
			initialGas:  100,
			expectedGas: 90,
			expectedDeltaRegs: deltaRegs{
				A0: uint64(HUH),
			},
			X: AccumulateContext{
				ServiceId: currentServiceID,
				AccumulationState: state.AccumulationState{
					ServiceState: service.ServiceState{
						currentServiceID: {
							Balance: 200,
							PreimageMeta: map[service.PreImageMetaKey]service.PreimageHistoricalTimeslots{
								{Hash: randomHash, Length: service.PreimageLength(256)}: {800}, // Invalid: not 2 timeslots
							},
						},
					},
				},
			},
			expectedX: AccumulateContext{
				ServiceId: currentServiceID,
				AccumulationState: state.AccumulationState{
					ServiceState: service.ServiceState{
						currentServiceID: {
							Balance: 200,
							PreimageMeta: map[service.PreImageMetaKey]service.PreimageHistoricalTimeslots{
								{Hash: randomHash, Length: service.PreimageLength(256)}: {800}, // State unchanged
							},
						},
					},
				},
			},
		}, {
			name: "solicit_insufficient_balance",
			fn:   fnWithExtra[jamtime.Timeslot](Solicit),
			alloc: alloc{
				A0: hash2bytes(randomHash),
			},
			initialRegs: deltaRegs{
				A1: 256,
			},
			extraParam:  jamtime.Timeslot(1000),
			initialGas:  100,
			expectedGas: 90,
			expectedDeltaRegs: deltaRegs{
				A0: uint64(FULL),
			},
			X: AccumulateContext{
				ServiceId: currentServiceID,
				AccumulationState: state.AccumulationState{
					ServiceState: service.ServiceState{
						currentServiceID: {
							Balance:      50, // Less than threshold
							PreimageMeta: map[service.PreImageMetaKey]service.PreimageHistoricalTimeslots{},
						},
					},
				},
			},
			expectedX: AccumulateContext{
				ServiceId: currentServiceID,
				AccumulationState: state.AccumulationState{
					ServiceState: service.ServiceState{
						currentServiceID: {
							Balance: 50,
							PreimageMeta: map[service.PreImageMetaKey]service.PreimageHistoricalTimeslots{
								{Hash: randomHash, Length: service.PreimageLength(256)}: {},
							},
						},
					},
				},
			},
		}, {
			name:              "forget_0",
			fn:                fnWithExtra[jamtime.Timeslot](Forget),
			extraParam:        jamtime.Timeslot(0),
			alloc:             alloc{A0: hash2bytes(randomHash)},
			initialRegs:       deltaRegs{A1: 123},
			expectedDeltaRegs: deltaRegs{A0: uint64(OK)},
			initialGas:        100,
			expectedGas:       90,
			X: AccumulateContext{
				ServiceId: currentServiceID,
				AccumulationState: state.AccumulationState{
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
			},
			expectedX: AccumulateContext{
				ServiceId: currentServiceID,
				AccumulationState: state.AccumulationState{
					ServiceState: service.ServiceState{
						currentServiceID: {
							PreimageMeta:   map[service.PreImageMetaKey]service.PreimageHistoricalTimeslots{},
							PreimageLookup: map[crypto.Hash][]byte{},
							CodeHash:       randomHash2,
							Balance:        111,
						},
					},
				},
			},
		}, {
			name:              "forget_1",
			fn:                fnWithExtra[jamtime.Timeslot](Forget),
			alloc:             alloc{A0: hash2bytes(randomHash)},
			initialRegs:       deltaRegs{A1: 123},
			expectedDeltaRegs: deltaRegs{A0: uint64(OK)},
			initialGas:        100,
			expectedGas:       90,
			extraParam:        randomTimeslot2,
			X: AccumulateContext{
				ServiceId: currentServiceID,
				AccumulationState: state.AccumulationState{
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
			},
			expectedX: AccumulateContext{
				ServiceId: currentServiceID,
				AccumulationState: state.AccumulationState{
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
			},
		}, {
			name:              "forget_2",
			fn:                fnWithExtra[jamtime.Timeslot](Forget),
			alloc:             alloc{A0: hash2bytes(randomHash)},
			initialRegs:       deltaRegs{A1: 123},
			expectedDeltaRegs: deltaRegs{A0: uint64(OK)},
			initialGas:        100,
			expectedGas:       90,
			extraParam:        randomTimeslot2 + jamtime.PreimageExpulsionPeriod + 1,
			X: AccumulateContext{
				ServiceId: currentServiceID,
				AccumulationState: state.AccumulationState{
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
			},
			expectedX: AccumulateContext{
				ServiceId: currentServiceID,
				AccumulationState: state.AccumulationState{
					ServiceState: service.ServiceState{
						currentServiceID: {
							PreimageMeta:   map[service.PreImageMetaKey]service.PreimageHistoricalTimeslots{},
							PreimageLookup: map[crypto.Hash][]byte{},
							CodeHash:       randomHash2,
							Balance:        111,
						},
					},
				},
			},
		}, {
			name:              "forget_3",
			fn:                fnWithExtra[jamtime.Timeslot](Forget),
			alloc:             alloc{A0: hash2bytes(randomHash)},
			initialRegs:       deltaRegs{A1: 123},
			expectedDeltaRegs: deltaRegs{A0: uint64(OK)},
			initialGas:        100,
			expectedGas:       90,
			extraParam:        randomTimeslot2 + jamtime.PreimageExpulsionPeriod + 1,
			X: AccumulateContext{
				ServiceId: currentServiceID,
				AccumulationState: state.AccumulationState{
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
			},
			expectedX: AccumulateContext{
				ServiceId: currentServiceID,
				AccumulationState: state.AccumulationState{
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
		},
		{
			name:       "yield",
			fn:         fnStd(Yield),
			initialGas: 100,
			alloc: alloc{
				A0: hash2bytes(randomHash),
			},
			X: AccumulateContext{
				ServiceId: 999,
			},
			expectedDeltaRegs: deltaRegs{
				A0: uint64(OK),
			},
			expectedGas: 90,
			expectedX: AccumulateContext{
				ServiceId:        999,
				AccumulationHash: &randomHash,
			},
		},
		{
			name:       "provide",
			fn:         fnWithExtra[block.ServiceId](Provide),
			extraParam: block.ServiceId(1),
			initialGas: 100,
			alloc: alloc{
				A1: hash2bytes(randomHash),
			},
			initialRegs: deltaRegs{A0: 1, A2: 32},
			X: AccumulateContext{
				AccumulationState: state.AccumulationState{
					ServiceState: service.ServiceState{
						1: {},
						2: {},
					},
				},
			},
			expectedDeltaRegs: deltaRegs{
				A0: uint64(OK),
			},
			expectedGas: 90,
			expectedX: AccumulateContext{
				AccumulationState: state.AccumulationState{
					ServiceState: service.ServiceState{
						1: {},
						2: {},
					},
				},
				ProvidedPreimages: []ProvidedPreimage{
					{ServiceId: 1, Data: hash2bytes(randomHash)},
				},
			},
		},
		{
			name:       "provide_already_provided",
			fn:         fnWithExtra[block.ServiceId](Provide),
			extraParam: block.ServiceId(1),
			initialGas: 100,
			alloc: alloc{
				A1: hash2bytes(randomHash),
			},
			initialRegs: deltaRegs{A0: 1, A2: 32},
			X: AccumulateContext{
				AccumulationState: state.AccumulationState{
					ServiceState: service.ServiceState{
						1: {},
						2: {},
					},
				},
				ProvidedPreimages: []ProvidedPreimage{
					{ServiceId: 1, Data: hash2bytes(randomHash)},
				},
			},
			expectedDeltaRegs: deltaRegs{
				A0: uint64(HUH),
			},
			expectedGas: 90,
			expectedX: AccumulateContext{
				AccumulationState: state.AccumulationState{
					ServiceState: service.ServiceState{
						1: {},
						2: {},
					},
				},
				ProvidedPreimages: []ProvidedPreimage{
					{ServiceId: 1, Data: hash2bytes(randomHash)},
				},
			},
		},
		{
			name:        "provide_service_not_found",
			fn:          fnWithExtra[block.ServiceId](Provide),
			extraParam:  block.ServiceId(1),
			initialGas:  100,
			initialRegs: deltaRegs{A0: 1},
			X: AccumulateContext{
				AccumulationState: state.AccumulationState{
					ServiceState: service.ServiceState{
						2: {},
					},
				},
			},
			expectedDeltaRegs: deltaRegs{
				A0: uint64(WHO),
			},
			expectedGas: 90,
			expectedX: AccumulateContext{
				AccumulationState: state.AccumulationState{
					ServiceState: service.ServiceState{
						2: {},
					},
				},
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mem, initialRegs, err := InitializeStandardProgram(pp, nil)
			if err != nil {
				t.Fatal(err)
			}
			rwAddress := RWAddressBase
			for addrReg, v := range tc.alloc {
				require.Greater(t, addrReg, S1)
				err = mem.Write(rwAddress, v)
				require.NoError(t, err)

				initialRegs[addrReg] = rwAddress
				rwAddress = rwAddress + uint64(len(v))
			}
			for i, v := range tc.initialRegs {
				initialRegs[i] = v
			}
			gasRemaining, regs, mem, ctxPair, err := tc.fn(Gas(tc.initialGas), initialRegs, mem, AccumulateContextPair{
				RegularCtx:     tc.X,
				ExceptionalCtx: tc.Y,
			}, tc.extraParam)
			require.ErrorIs(t, err, tc.err)
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

type hostCall func(Gas, Registers, Memory, AccumulateContextPair, any) (Gas, Registers, Memory, AccumulateContextPair, error)
type alloc map[Reg][]byte
type deltaRegs map[Reg]uint64

func fixedSizeBytes(size int, b []byte) []byte {
	bb := make([]byte, size)
	copy(bb, b)
	return bb
}

func fnStd(
	fn func(Gas, Registers, Memory, AccumulateContextPair) (Gas, Registers, Memory, AccumulateContextPair, error),
) hostCall {
	return func(g Gas, r Registers, m Memory, c AccumulateContextPair, _ any) (
		Gas, Registers, Memory, AccumulateContextPair, error,
	) {
		return fn(g, r, m, c)
	}
}

func fnWithExtra[T any](
	fn func(Gas, Registers, Memory, AccumulateContextPair, T) (Gas, Registers, Memory, AccumulateContextPair, error),
) hostCall {
	return func(g Gas, r Registers, m Memory, c AccumulateContextPair, extra any) (
		Gas, Registers, Memory, AccumulateContextPair, error,
	) {
		v, ok := extra.(T)
		if !ok {
			return g, r, m, c, fmt.Errorf("invalid type for extra param: expected %T", *new(T))
		}
		return fn(g, r, m, c, v)
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
