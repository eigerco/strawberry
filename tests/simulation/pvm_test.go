//go:build integration

package simulation

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/eigerco/strawberry/internal/testutils"
	"github.com/stretchr/testify/assert"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/eigerco/strawberry/internal/block"
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/polkavm"
	"github.com/eigerco/strawberry/internal/safrole"
	"github.com/eigerco/strawberry/internal/service"
	"github.com/eigerco/strawberry/internal/state"
	"github.com/eigerco/strawberry/internal/state/serialization"
	"github.com/eigerco/strawberry/internal/state/serialization/statekey"
	"github.com/eigerco/strawberry/internal/statetransition"
	"github.com/eigerco/strawberry/pkg/serialization/codec/jam"
)

type GenesisStateJson struct {
	Id                 string            `json:"id"`
	GenesisState       map[string]string `json:"genesis_state"`
	Bootnodes          []string          `json:"bootnodes"`
	ProtocolParameters string            `json:"protocol_parameters"`
	GenesisHeader      string            `json:"genesis_header"`
}

func TestPVM(t *testing.T) {

	data, err := os.ReadFile("./simulation_pvm_genesis.json")
	require.NoError(t, err)

	genesis := &GenesisStateJson{}
	err = json.Unmarshal(data, genesis)
	require.NoError(t, err)

	serializedState := make(map[statekey.StateKey][]byte)
	for key, val := range genesis.GenesisState {
		keyBytes, err := hex.DecodeString(key)
		require.NoError(t, err)

		valBytes, err := hex.DecodeString(val)
		require.NoError(t, err)

		serializedState[statekey.StateKey(keyBytes)] = valBytes
	}
	genesisState, err := serialization.DeserializeState(serializedState)
	require.NoError(t, err)
	headerBytes, err := hex.DecodeString(genesis.GenesisHeader)
	require.NoError(t, err)

	genesisHeader := &block.Header{}
	err = jam.Unmarshal(headerBytes, genesisHeader)
	require.NoError(t, err)

	accumulator := statetransition.NewAccumulator(&genesisState, genesisHeader, 1)

	t.Run("create service", func(t *testing.T) {

		codeBytes := []byte("test service code to provision")

		memo := service.Memo{}
		copy(memo[:], "memo 123")
		createSvcReq := CreateService{
			CodeHash:     crypto.HashData(codeBytes),
			CodeLen:      uint64(len(codeBytes)),
			MinItemGas:   123,
			MinMemoGas:   234,
			Endowment:    123456,
			Memo:         memo,
			Registration: nil,
		}

		services := genesisState.Services.Clone()
		// provide the code preimage to state
		services[0].PreimageLookup[createSvcReq.CodeHash] = codeBytes

		newState, transfers, _, _, providedPreimages := invokePVM(t, genesisState, services, accumulator,
			[]*Instruction{NewInstruction(createSvcReq)})

		key := storageKey(t, 0, []byte("created"))
		newServiceIdBytes := newState.ServiceState[0].Storage[key]

		newServiceId := block.ServiceId(0)
		err = jam.Unmarshal(newServiceIdBytes, &newServiceId)
		assert.NoError(t, err)

		// test service creation
		assert.Equal(t, newServiceId, block.ServiceId(644491146))
		assert.Equal(t, map[service.PreImageMetaKey]service.PreimageHistoricalTimeslots{
			{createSvcReq.CodeHash, service.PreimageLength(createSvcReq.CodeLen)}: {},
		}, newState.ServiceState[newServiceId].PreimageMeta)
		assert.Equal(t, createSvcReq.CodeHash, newState.ServiceState[newServiceId].CodeHash)
		assert.Equal(t, createSvcReq.MinItemGas, newState.ServiceState[newServiceId].GasLimitForAccumulator)
		assert.Equal(t, createSvcReq.MinMemoGas, newState.ServiceState[newServiceId].GasLimitOnTransfer)

		// test preimage provision
		assert.Equal(t, []polkavm.ProvidedPreimage{{newServiceId, codeBytes}}, providedPreimages)

		// test transfers
		assert.Equal(t, []service.DeferredTransfer{{
			SenderServiceIndex:   0,
			ReceiverServiceIndex: newServiceId,
			Balance:              uint64(createSvcReq.Endowment),
			Memo:                 createSvcReq.Memo,
			GasLimit:             uint64(createSvcReq.MinMemoGas),
		}}, transfers)
	})

	t.Run("upgrade", func(t *testing.T) {
		upgrade := Upgrade{
			CodeHash:   testutils.RandomHash(t),
			MinItemGas: 456,
			MinMemoGas: 567,
		}
		newState, _, _, _, _ := invokePVM(t, genesisState, genesisState.Services.Clone(), accumulator,
			[]*Instruction{NewInstruction(upgrade)})
		assert.Equal(t, upgrade.CodeHash, newState.ServiceState[0].CodeHash)
		assert.Equal(t, upgrade.MinItemGas, newState.ServiceState[0].GasLimitForAccumulator)
		assert.Equal(t, upgrade.MinMemoGas, newState.ServiceState[0].GasLimitOnTransfer)
	})
	t.Run("transfer", func(t *testing.T) {
		memo := service.Memo{}
		copy(memo[:], "memo 321")
		transfer := Transfer{
			Destination: 644491146,
			Amount:      1000,
			GasLimit:    1,
			Memo:        memo,
		}
		newState, _, _, _, _ := invokePVM(t, genesisState, genesisState.Services.Clone(), accumulator,
			[]*Instruction{NewInstruction(transfer)})
		transferredData := struct {
			Destination block.ServiceId
			Amount      Balance
			Memo        service.Memo
		}{}
		key := storageKey(t, 0, []byte("transferred"))
		transferredDataBytes := newState.ServiceState[0].Storage[key]
		err = jam.Unmarshal(transferredDataBytes, &transferredData)
		require.NoError(t, err)

		assert.Equal(t, transfer.Destination, transferredData.Destination)
		assert.Equal(t, transfer.Amount, transferredData.Amount)
		assert.Equal(t, transfer.Memo, transferredData.Memo)
	})
	t.Run("zombify", func(t *testing.T) {
		zombify := Zombify{Ejector: 644491146}

		services := genesisState.Services.Clone()
		// remove all lookup images
		// it is required to have no preimages to zombify the service
		for preimageKey, preimageVal := range genesisState.Services[0].PreimageLookup {
			if preimageKey == services[0].CodeHash {
				continue
			}
			delete(services[0].PreimageMeta, service.PreImageMetaKey{
				Hash:   preimageKey,
				Length: service.PreimageLength(len(preimageVal)),
			})
			delete(services[0].PreimageLookup, preimageKey)
		}

		newState, _, _, _, _ := invokePVM(t, genesisState, services, accumulator,
			[]*Instruction{NewInstruction(zombify)})

		newCodeHash, err := jam.Marshal(struct {
			ServiceId block.ServiceId
			Rest      [28]byte
		}{644491146, [28]byte{}})
		require.NoError(t, err)

		assert.Equal(t, crypto.Hash(newCodeHash), newState.ServiceState[0].CodeHash)
		assert.Equal(t, uint64(0), newState.ServiceState[0].GasLimitForAccumulator)
		assert.Equal(t, uint64(0), newState.ServiceState[0].GasLimitOnTransfer)
	})
	t.Run("eject", func(t *testing.T) {
		serviceId := block.ServiceId(644491146)

		bootServiceIdEncoded, err := jam.Marshal(struct {
			ServiceId block.ServiceId `jam:"length=32"`
		}{0})
		require.NoError(t, err)

		eject := Eject{
			Target:   serviceId,
			CodeHash: crypto.Hash(bootServiceIdEncoded),
		}

		services := genesisState.Services.Clone()
		code := make([]byte, 100)
		copy(code, "code 123")

		services[serviceId] = service.ServiceAccount{
			CodeHash:       crypto.Hash(bootServiceIdEncoded),
			PreimageLookup: map[crypto.Hash][]byte{crypto.HashData(code): code},
			PreimageMeta: map[service.PreImageMetaKey]service.PreimageHistoricalTimeslots{
				{crypto.Hash(bootServiceIdEncoded), service.PreimageLength(0)}: {0, 0},
			},
		}
		newState, _, _, _, _ := invokePVM(t, genesisState, services, accumulator,
			[]*Instruction{NewInstruction(eject)})

		_, ok := newState.ServiceState[serviceId]
		assert.False(t, ok, "Service not ejected")
	})
	t.Run("delete items", func(t *testing.T) {

		deleteItems := DeleteItems{
			StorageItems: [][]byte{[]byte("test_storage_1"), []byte("test_storage_2")},
		}

		services := genesisState.Services.Clone()
		svc := services[0]
		svc.Storage = map[statekey.StateKey][]byte{
			storageKey(t, 0, []byte("test_storage_1")): []byte("test_storage_1"),
			storageKey(t, 0, []byte("test_storage_2")): []byte("test_storage_2"),
		}
		services[0] = svc
		newState, _, _, _, _ := invokePVM(t, genesisState, services, accumulator,
			[]*Instruction{NewInstruction(deleteItems)})

		assert.Len(t, newState.ServiceState[0].Storage, 0)
	})
	t.Run("looked up", func(t *testing.T) {
		someData := []byte("some data 123")
		lookedUp := LookedUp{
			Data: someData,
		}

		newState, _, _, _, _ := invokePVM(t, genesisState, genesisState.Services.Clone(), accumulator,
			[]*Instruction{NewInstruction(lookedUp)})

		assert.Equal(t, someData, newState.ServiceState[0].Storage[storageKey(t, 0, []byte("looked_up"))])
	})
	t.Run("imported", func(t *testing.T) {
		imported := Imported{
			Data: [][]byte{[]byte("key1"), []byte("key2")},
		}

		newState, _, _, _, _ := invokePVM(t, genesisState, genesisState.Services.Clone(), accumulator,
			[]*Instruction{NewInstruction(imported)})
		assert.Equal(t, uint32(2), binary.LittleEndian.Uint32(newState.ServiceState[0].Storage[storageKey(t, 0, []byte("imported"))]))
		assert.Equal(t, []byte("key1"), newState.ServiceState[0].Storage[storageKey(t, 0, []byte("import-0"))])
		assert.Equal(t, []byte("key2"), newState.ServiceState[0].Storage[storageKey(t, 0, []byte("import-1"))])
	})
	t.Run("exported", func(t *testing.T) {
		exported := Exported{
			Count: 12,
		}

		newState, _, _, _, _ := invokePVM(t, genesisState, genesisState.Services.Clone(), accumulator,
			[]*Instruction{NewInstruction(exported)})
		assert.Equal(t, uint64(12), binary.LittleEndian.Uint64(newState.ServiceState[0].Storage[storageKey(t, 0, []byte("exported"))]))
	})

	t.Run("solicit", func(t *testing.T) {
		somePreimage := []byte("test 123")
		solicit := Solicit{
			Hash: crypto.HashData(somePreimage),
			Len:  uint64(len(somePreimage)),
		}

		services := genesisState.Services.Clone()
		svc := services[0]
		svc.Storage = map[statekey.StateKey][]byte{
			storageKey(t, 0, []byte("test_storage_1")): []byte("test_storage_1"),
			storageKey(t, 0, []byte("test_storage_2")): []byte("test_storage_2"),
		}
		services[0] = svc
		newState, _, _, _, _ := invokePVM(t, genesisState, services, accumulator,
			[]*Instruction{NewInstruction(solicit)})
		assert.Equal(t, crypto.HashData(somePreimage), crypto.Hash(newState.ServiceState[0].Storage[storageKey(t, 0, []byte("requested"))]))
	})
	t.Run("forget", func(t *testing.T) {
		somePreimage := []byte("test 123")
		forget := Forget{
			Hash: crypto.HashData(somePreimage),
			Len:  uint64(len(somePreimage)),
		}

		services := genesisState.Services.Clone()
		services[0].PreimageMeta[service.PreImageMetaKey{
			Hash:   crypto.HashData(somePreimage),
			Length: service.PreimageLength(len(somePreimage)),
		}] = service.PreimageHistoricalTimeslots{0}
		newState, _, _, _, _ := invokePVM(t, genesisState, services, accumulator,
			[]*Instruction{NewInstruction(forget)})

		assert.Equal(t, crypto.HashData(somePreimage), crypto.Hash(newState.ServiceState[0].Storage[storageKey(t, 0, []byte("unrequested"))]))
	})
	t.Run("assign", func(t *testing.T) {
		assign := Assign{
			Core: 1,
			Queue: state.PendingAuthorizersQueue{
				testutils.RandomHash(t),
				testutils.RandomHash(t),
				testutils.RandomHash(t),
				testutils.RandomHash(t),
			},
		}

		newState, _, _, _, _ := invokePVM(t, genesisState, genesisState.Services.Clone(), accumulator,
			[]*Instruction{NewInstruction(assign)})
		assert.Equal(t, assign.Queue, newState.PendingAuthorizersQueues[assign.Core])
	})
	t.Run("bless", func(t *testing.T) {
		bless := Bless{
			Manager:   3,
			Assign:    4,
			Designate: 5,
			AutoAcc: []ServiceIdAndGas{
				{6, 100},
				{7, 200},
				{13, 6000},
			},
		}

		newState, _, _, _, _ := invokePVM(t, genesisState, genesisState.Services.Clone(), accumulator,
			[]*Instruction{NewInstruction(bless)})
		assert.Equal(t, block.ServiceId(3), newState.PrivilegedServices.ManagerServiceId)
		assert.Equal(t, block.ServiceId(4), newState.PrivilegedServices.AssignServiceId)
		assert.Equal(t, block.ServiceId(5), newState.PrivilegedServices.DesignateServiceId)
		assert.Equal(t, map[block.ServiceId]uint64{6: 100, 7: 200, 13: 6000}, newState.PrivilegedServices.AmountOfGasPerServiceId)
	})
	t.Run("designate", func(t *testing.T) {
		designate := Designate{
			Keys: safrole.ValidatorsData{
				testutils.RandomValidatorKey(t),
				testutils.RandomValidatorKey(t),
				testutils.RandomValidatorKey(t),
				testutils.RandomValidatorKey(t),
				testutils.RandomValidatorKey(t),
				testutils.RandomValidatorKey(t),
			},
		}

		newState, _, _, _, _ := invokePVM(t, genesisState, genesisState.Services.Clone(), accumulator,
			[]*Instruction{NewInstruction(designate)})
		assert.Equal(t, designate.Keys, newState.ValidatorKeys)
	})
	t.Run("yield", func(t *testing.T) {
		yield := Yield{
			Hash: testutils.RandomHash(t),
		}

		_, _, yieldHash, _, _ := invokePVM(t, genesisState, genesisState.Services.Clone(), accumulator,
			[]*Instruction{NewInstruction(yield)})
		require.NotNil(t, yieldHash)
		assert.Equal(t, yield.Hash, *yieldHash)
	})
	t.Run("provide", func(t *testing.T) {
		provide := Provide{
			ServiceId: 0,
			Preimage:  testutils.RandomHash(t),
		}

		_, _, _, _, providedPreimages := invokePVM(t, genesisState, genesisState.Services.Clone(), accumulator,
			[]*Instruction{NewInstruction(provide)})
		assert.Equal(t, []polkavm.ProvidedPreimage{{0, provide.Preimage[:]}}, providedPreimages)
	})
	t.Run("checkpoint1", func(t *testing.T) {
		_, _, _, _, providedPreimages := invokePVM(t, genesisState, genesisState.Services.Clone(), accumulator,
			[]*Instruction{
				NewInstruction(Checkpoint{}),
				NewInstruction(Provide{
					ServiceId: 0,
					Preimage:  testutils.RandomHash(t),
				}),
				NewInstruction(Panic{}),
			})
		assert.Len(t, providedPreimages, 0)
	})
	t.Run("checkpoint2", func(t *testing.T) {
		_, _, _, _, providedPreimages := invokePVM(t, genesisState, genesisState.Services.Clone(), accumulator,
			[]*Instruction{
				NewInstruction(Checkpoint{}),
				NewInstruction(Provide{
					ServiceId: 0,
					Preimage:  testutils.RandomHash(t),
				}),
				NewInstruction(Checkpoint{}),
				NewInstruction(Panic{}),
			})
		assert.Len(t, providedPreimages, 1)
	})
	t.Run("random storage accumulate", func(t *testing.T) {
		key1 := testutils.RandomHash(t)
		key2 := testutils.RandomHash(t)
		randomStorageAccumulate := RandomStorageAccumulate{
			Inner: RandomStorageAccumulateSuccess{
				Items: []RandomRefineItem{{Key: key1}, {Key: key2}},
			},
		}

		newState, _, _, _, _ := invokePVM(t, genesisState, genesisState.Services.Clone(), accumulator, []*Instruction{NewInstruction(randomStorageAccumulate)})
		assert.Equal(t, uint64(2), binary.LittleEndian.Uint64(
			newState.ServiceState[0].Storage[storageKey(t, 0, []byte("count_random_storage"))],
		))
		assert.Equal(t, key1[:], newState.ServiceState[0].Storage[storageKey(t, 0, key1[:])])
		assert.Equal(t, key2[:], newState.ServiceState[0].Storage[storageKey(t, 0, key2[:])])
	})
	t.Run("benchmark", func(t *testing.T) {
		benchmark := Benchmark{}

		newState, _, _, _, _ := invokePVM(t, genesisState, genesisState.Services.Clone(), accumulator, []*Instruction{NewInstruction(benchmark)})
		for i := range 1000 {
			assert.Equal(t, []byte(fmt.Sprintf("%d", i)), newState.ServiceState[0].Storage[storageKey(t, 0, []byte(fmt.Sprintf("item-1-%d", i)))])
		}
	})
}

func invokePVM(t *testing.T, genesisState state.State, services service.ServiceState, accumulator *statetransition.Accumulator, instrs []*Instruction) (state.AccumulationState, []service.DeferredTransfer, *crypto.Hash, uint64, []polkavm.ProvidedPreimage) {
	output, err := jam.Marshal(instrs)
	require.NoError(t, err)

	return accumulator.InvokePVM(state.AccumulationState{
		PrivilegedServices:       genesisState.PrivilegedServices,
		ServiceState:             services,
		ValidatorKeys:            genesisState.ValidatorState.QueuedValidators,
		PendingAuthorizersQueues: genesisState.PendingAuthorizersQueues,
	}, 1, 0, 100000000, []state.AccumulationOperand{{
		OutputOrError: block.WorkResultOutputOrError{Inner: output},
	}})
}

func storageKey(t *testing.T, serviceId block.ServiceId, keyData []byte) statekey.StateKey {
	serviceIdBytes, err := jam.Marshal(serviceId)
	require.NoError(t, err)

	hashInput := append(serviceIdBytes, keyData...)
	k, err := statekey.NewStorage(serviceId, crypto.HashData(hashInput))
	require.NoError(t, err)

	return k
}

func NewInstruction(v InstructionType) *Instruction {
	return &Instruction{
		inner: v,
	}
}

type Instruction struct {
	inner InstructionType
}

func (i *Instruction) IndexValue() (index uint, value any, err error) {
	switch i.inner.(type) {
	case CreateService:
		return 0, i.inner, nil
	case Upgrade:
		return 1, i.inner, nil
	case Transfer:
		return 2, i.inner, nil
	case Zombify:
		return 3, i.inner, nil
	case Eject:
		return 4, i.inner, nil
	case DeleteItems:
		return 5, i.inner, nil
	case Solicit:
		return 6, i.inner, nil
	case Forget:
		return 7, i.inner, nil
	case Lookup:
		return 8, i.inner, nil
	case Import:
		return 9, i.inner, nil
	case Export:
		return 10, i.inner, nil
	case Bless:
		return 11, i.inner, nil
	case Assign:
		return 12, i.inner, nil
	case Designate:
		return 13, i.inner, nil
	case Yield:
		return 14, i.inner, nil
	case Checkpoint:
		return 15, i.inner, nil
	case Panic:
		return 16, i.inner, nil
	case Provide:
		return 17, i.inner, nil
	case LookedUp:
		return 18, i.inner, nil
	case Imported:
		return 19, i.inner, nil
	case Exported:
		return 20, i.inner, nil
	case RandomStorageRefine:
		return 21, i.inner, nil
	case RandomStorageAccumulate:
		return 22, i.inner, nil
	case Benchmark:
		return 23, i.inner, nil
	}
	return 0, nil, jam.ErrUnsupportedEnumTypeValue
}

func (i *Instruction) ValueAt(index uint) (value any, err error) {
	switch index {
	case 0:
		return CreateService{}, nil
	case 1:
		return Upgrade{}, nil
	case 2:
		return Transfer{}, nil
	case 3:
		return Zombify{}, nil
	case 4:
		return Eject{}, nil
	case 5:
		return DeleteItems{}, nil
	case 6:
		return Solicit{}, nil
	case 7:
		return Forget{}, nil
	case 8:
		return Lookup{}, nil
	case 9:
		return Import{}, nil
	case 10:
		return Export{}, nil
	case 11:
		return Bless{}, nil
	case 12:
		return Assign{}, nil
	case 13:
		return Designate{}, nil
	case 14:
		return Yield{}, nil
	case 15:
		return Checkpoint{}, nil
	case 16:
		return Panic{}, nil
	case 17:
		return Provide{}, nil
	case 18:
		return LookedUp{}, nil
	case 19:
		return Imported{}, nil
	case 20:
		return Exported{}, nil
	case 21:
		return RandomStorageRefine{}, nil
	case 22:
		return RandomStorageAccumulate{}, nil
	case 23:
		return Benchmark{}, nil
	}
	return nil, jam.ErrUnsupportedEnumTypeValue
}

func (i *Instruction) SetValue(value any) error {
	switch value := value.(type) {
	case InstructionType:
		i.inner = value
		return nil

	default:
		return fmt.Errorf(jam.ErrUnsupportedType, value)
	}
}

type Balance uint64
type CoreIndex uint16

type InstructionType interface {
	IsInstructionType()
}

type CreateService struct {
	CodeHash     crypto.Hash
	CodeLen      uint64
	MinItemGas   uint64
	MinMemoGas   uint64
	Endowment    Balance
	Memo         service.Memo
	Registration *[]byte
}

func (c CreateService) IsInstructionType() {}

type Upgrade struct {
	CodeHash   crypto.Hash
	MinItemGas uint64
	MinMemoGas uint64
}

func (c Upgrade) IsInstructionType() {}

type Transfer struct {
	Destination block.ServiceId
	Amount      Balance
	GasLimit    uint64
	Memo        service.Memo
}

func (c Transfer) IsInstructionType() {}

type Zombify struct {
	Ejector block.ServiceId
}

func (c Zombify) IsInstructionType() {}

type Eject struct {
	Target   block.ServiceId
	CodeHash crypto.Hash
}

func (c Eject) IsInstructionType() {}

type DeleteItems struct {
	StorageItems [][]byte
}

func (c DeleteItems) IsInstructionType() {}

type Solicit struct {
	Hash crypto.Hash
	Len  uint64
}

func (c Solicit) IsInstructionType() {}

type Forget struct {
	Hash crypto.Hash
	Len  uint64
}

func (c Forget) IsInstructionType() {}

type Lookup struct {
	Service block.ServiceId
	Hash    crypto.Hash
}

func (c Lookup) IsInstructionType() {}

type Import struct {
	Items []IndexAndLength
}

func (c Import) IsInstructionType() {}

type IndexAndLength struct {
	Index  uint64
	Length uint64
}

type Export struct {
	Data [][]byte
}

func (c Export) IsInstructionType() {}

type Bless struct {
	Manager   block.ServiceId
	Assign    block.ServiceId
	Designate block.ServiceId
	AutoAcc   []ServiceIdAndGas
}

func (Bless) IsInstructionType() {}

type ServiceIdAndGas struct {
	ServiceId block.ServiceId
	Gas       uint64
}

type Assign struct {
	Core  CoreIndex
	Queue state.PendingAuthorizersQueue
}

func (c Assign) IsInstructionType() {}

type Designate struct {
	Keys safrole.ValidatorsData
}

func (Designate) IsInstructionType() {}

type Yield struct {
	Hash crypto.Hash
}

func (Yield) IsInstructionType() {}

type Checkpoint struct{}

func (Checkpoint) IsInstructionType() {}

type Panic struct{}

func (Panic) IsInstructionType() {}

type Provide struct {
	ServiceId block.ServiceId
	Preimage  crypto.Hash
}

func (Provide) IsInstructionType() {}

type LookedUp struct {
	Data []byte
}

func (LookedUp) IsInstructionType() {}

type Imported struct {
	Data [][]byte
}

func (Imported) IsInstructionType() {}

type Exported struct {
	Count uint64
}

func (Exported) IsInstructionType() {}

type RandomStorageRefine struct{}

func (RandomStorageRefine) IsInstructionType() {}

type RandomRefineItem struct {
	Key [32]byte
}
type RandomStorageAccumulate struct {
	Inner any
}

type RandomStorageAccumulateSuccess struct {
	Items []RandomRefineItem
}
type RandomStorageAccumulateError struct {
	Err struct{}
}

func (a RandomStorageAccumulate) IndexValue() (index uint, value any, err error) {
	switch a.Inner.(type) {
	case RandomStorageAccumulateSuccess:
		return 0, a.Inner, nil
	case RandomStorageAccumulateError:
		return 1, a.Inner, nil
	}

	return 0, nil, jam.ErrUnsupportedEnumTypeValue
}

func (a RandomStorageAccumulate) ValueAt(index uint) (value any, err error) {
	switch index {
	case 0:
		return RandomStorageAccumulateSuccess{}, nil
	case 1:
		return RandomStorageAccumulateError{}, nil
	}
	return nil, jam.ErrUnsupportedEnumTypeValue
}

func (a RandomStorageAccumulate) SetValue(value any) error {
	switch value := value.(type) {
	case RandomStorageAccumulateSuccess:
		a.Inner = value
		return nil
	case RandomStorageAccumulateError:
		a.Inner = value
		return nil
	default:
		return fmt.Errorf(jam.ErrUnsupportedType, value)
	}
}

func (RandomStorageAccumulate) IsInstructionType() {}

type Benchmark struct{}

func (Benchmark) IsInstructionType() {}
