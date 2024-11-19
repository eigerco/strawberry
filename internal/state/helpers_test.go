package state

import (
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"fmt"
	"testing"

	"github.com/eigerco/strawberry/internal/block"
	"github.com/eigerco/strawberry/internal/common"
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/safrole"
	"github.com/eigerco/strawberry/internal/service"
	"github.com/eigerco/strawberry/internal/testutils"
	"github.com/eigerco/strawberry/internal/validator"
	"github.com/eigerco/strawberry/pkg/serialization/codec/jam"
	"github.com/stretchr/testify/require"
)

func RandomValidatorsData(t *testing.T) safrole.ValidatorsData {
	var validatorsData safrole.ValidatorsData
	for i := 0; i < len(validatorsData); i++ {
		validatorsData[i] = crypto.ValidatorKey{
			Bandersnatch: testutils.RandomBandersnatchPublicKey(t),
			Ed25519:      testutils.RandomED25519PublicKey(t),
			Bls:          testutils.RandomBlsKey(t),
			Metadata:     testutils.RandomMetadataKey(t),
		}
	}
	return validatorsData
}

func RandomTickets(t *testing.T) []block.Ticket {
	var tickets []block.Ticket
	for i := 0; i < 10; i++ {
		tickets = append(tickets, block.Ticket{Identifier: testutils.RandomBandersnatchOutputHash(t)})
	}
	return tickets
}

func RandomTicketBodies(t *testing.T) safrole.TicketsBodies {
	var tickets safrole.TicketsBodies
	for i := 0; i < 10; i++ {
		tickets[i] = block.Ticket{Identifier: testutils.RandomBandersnatchOutputHash(t)}
	}
	return tickets
}

func RandomEpochKeys(t *testing.T) crypto.EpochKeys {
	var epochKeys crypto.EpochKeys
	for i := 0; i < 10; i++ {
		epochKeys[i] = testutils.RandomBandersnatchPublicKey(t)
	}
	return epochKeys
}

func RandomServiceAccount(t *testing.T) service.ServiceAccount {
	return service.ServiceAccount{
		Storage:                map[crypto.Hash][]byte{testutils.RandomHash(t): []byte("data")},
		PreimageLookup:         map[crypto.Hash][]byte{testutils.RandomHash(t): []byte("preimage")},
		PreimageMeta:           map[service.PreImageMetaKey]service.PreimageHistoricalTimeslots{{Hash: testutils.RandomHash(t), Length: 32}: {testutils.RandomTimeslot()}},
		CodeHash:               testutils.RandomHash(t),
		Balance:                testutils.RandomUint64(),
		GasLimitForAccumulator: testutils.RandomUint64(),
		GasLimitOnTransfer:     testutils.RandomUint64(),
	}
}

func RandomPrivilegedServices() service.PrivilegedServices {
	amountOfGasPerServiceId := map[block.ServiceId]uint64{
		block.ServiceId(123): 12344,
		block.ServiceId(234): 23455,
		block.ServiceId(345): 34566,
	}
	return service.PrivilegedServices{
		ManagerServiceId:        block.ServiceId(123),
		AssignServiceId:         block.ServiceId(234),
		DesignateServiceId:      block.ServiceId(345),
		AmountOfGasPerServiceId: amountOfGasPerServiceId,
	}
}

func RandomEntropyPool(t *testing.T) EntropyPool {
	return EntropyPool{testutils.RandomHash(t), testutils.RandomHash(t), testutils.RandomHash(t), testutils.RandomHash(t)}
}

func RandomCoreAuthorizersPool(t *testing.T) CoreAuthorizersPool {
	var pool CoreAuthorizersPool
	for i := range pool {
		for j := 0; j < MaxAuthorizersPerCore; j++ {
			pool[i] = append(pool[i], testutils.RandomHash(t))
		}
	}
	return pool
}

func RandomPendingAuthorizersQueues(t *testing.T) PendingAuthorizersQueues {
	var queue PendingAuthorizersQueues
	for i := range queue {
		for j := 0; j < PendingAuthorizersQueueSize; j++ {
			queue[i][j] = testutils.RandomHash(t)
		}
	}
	return queue
}

func RandomCoreAssignments(t *testing.T) CoreAssignments {
	var assignments CoreAssignments
	for i := range assignments {
		assignments[i] = Assignment{
			WorkReport: &block.WorkReport{
				WorkPackageSpecification: block.WorkPackageSpecification{WorkPackageHash: testutils.RandomHash(t)},
				RefinementContext: block.RefinementContext{
					Anchor:                  block.RefinementContextAnchor{HeaderHash: testutils.RandomHash(t)},
					LookupAnchor:            block.RefinementContextLookupAnchor{HeaderHash: testutils.RandomHash(t), Timeslot: testutils.RandomTimeslot()},
					PrerequisiteWorkPackage: nil,
				},
				CoreIndex:      uint16(i),
				AuthorizerHash: testutils.RandomHash(t),
				Output:         []byte("output"),
				WorkResults:    []block.WorkResult{RandomWorkResult(t)},
			},
			Time: testutils.RandomTimeslot(),
		}
	}
	return assignments
}

func RandomWorkResult(t *testing.T) block.WorkResult {
	output := block.WorkResultOutputOrError{}
	err := output.SetValue([]byte("output"))
	require.NoError(t, err)

	return block.WorkResult{
		ServiceId:              block.ServiceId(567),
		ServiceHashCode:        testutils.RandomHash(t),
		PayloadHash:            testutils.RandomHash(t),
		GasPrioritizationRatio: testutils.RandomUint64(),
		Output:                 output,
	}
}

func RandomAccumulationQueue(t *testing.T) AccumulationQueue {
	var queue AccumulationQueue
	for i := 0; i < len(queue); i++ {
		// For each timeslot, create a random slice of WorkReportWithUnAccumulatedDependencies
		numReports := testutils.RandomUint32()%5 + 1 // Random number of work reports (1-5)
		for j := 0; j < int(numReports); j++ {
			queue[i] = append(queue[i], WorkReportWithUnAccumulatedDependencies{
				WorkReport:   RandomWorkReport(t),
				Dependencies: RandomHashSet(t, 5), // Random set of crypto.Hash
			})
		}
	}
	return queue
}

func RandomAccumulationHistory(t *testing.T) AccumulationHistory {
	var history AccumulationHistory
	for i := 0; i < len(history); i++ {
		numEntries := testutils.RandomUint32()%5 + 1 // Random number of map entries (1-5)
		history[i] = make(map[crypto.Hash]struct{})
		for j := 0; j < int(numEntries); j++ {
			history[i][testutils.RandomHash(t)] = struct{}{}
		}
	}
	return history
}

func RandomWorkReport(t *testing.T) block.WorkReport {
	return block.WorkReport{
		WorkPackageSpecification: block.WorkPackageSpecification{
			WorkPackageHash: testutils.RandomHash(t),
		},
		RefinementContext: block.RefinementContext{
			Anchor: block.RefinementContextAnchor{
				HeaderHash: testutils.RandomHash(t),
			},
			LookupAnchor: block.RefinementContextLookupAnchor{
				HeaderHash: testutils.RandomHash(t),
				Timeslot:   testutils.RandomTimeslot(),
			},
		},
		CoreIndex:      testutils.RandomUint16(),
		AuthorizerHash: testutils.RandomHash(t),
		Output:         []byte("random output"),
		WorkResults:    []block.WorkResult{RandomWorkResult(t)},
	}
}

func RandomHashSet(t *testing.T, maxSize int) map[crypto.Hash]struct{} {
	set := make(map[crypto.Hash]struct{})
	numEntries := testutils.RandomUint32()%uint32(maxSize) + 1
	for i := 0; i < int(numEntries); i++ {
		set[testutils.RandomHash(t)] = struct{}{}
	}
	return set
}

func RandomBlockState(t *testing.T) BlockState {
	var state BlockState
	state.HeaderHash = testutils.RandomHash(t)
	state.StateRoot = testutils.RandomHash(t)
	h := testutils.RandomHash(t)
	state.AccumulationResultMMR = []*crypto.Hash{&h}
	workReportHashes := make(map[crypto.Hash]crypto.Hash)
	for i := uint16(0); i < common.TotalNumberOfCores; i++ {
		workReportHashes[testutils.RandomHash(t)] = testutils.RandomHash(t)
	}
	state.WorkReportHashes = workReportHashes
	return state
}

func RandomValidatorState(t *testing.T) validator.ValidatorState {
	return validator.ValidatorState{
		CurrentValidators:  RandomValidatorsData(t),
		ArchivedValidators: RandomValidatorsData(t),
		QueuedValidators:   RandomValidatorsData(t),
		SafroleState:       RandomSafroleStateWithTicketBodies(t),
	}
}

func RandomValidatorStatistics() validator.ValidatorStatistics {
	return validator.ValidatorStatistics{
		NumOfBlocks:                 testutils.RandomUint32(),
		NumOfTickets:                testutils.RandomUint64(),
		NumOfPreimages:              testutils.RandomUint64(),
		NumOfBytesAllPreimages:      testutils.RandomUint64(),
		NumOfGuaranteedReports:      testutils.RandomUint64(),
		NumOfAvailabilityAssurances: testutils.RandomUint64(),
	}
}

func RandomValidatorStatisticsState() validator.ValidatorStatisticsState {
	return validator.ValidatorStatisticsState{
		[common.NumberOfValidators]validator.ValidatorStatistics{RandomValidatorStatistics(), RandomValidatorStatistics()},
		[common.NumberOfValidators]validator.ValidatorStatistics{RandomValidatorStatistics(), RandomValidatorStatistics()},
	}
}

func RandomJudgements(t *testing.T) Judgements {
	offendingValidators := make([]ed25519.PublicKey, 5)
	for i := range offendingValidators {
		offendingValidators[i] = testutils.RandomED25519PublicKey(t)
	}
	return Judgements{
		BadWorkReports:      []crypto.Hash{testutils.RandomHash(t)},
		GoodWorkReports:     []crypto.Hash{testutils.RandomHash(t)},
		WonkyWorkReports:    []crypto.Hash{testutils.RandomHash(t)},
		OffendingValidators: offendingValidators,
	}
}

func RandomSafroleStateWithTicketBodies(t *testing.T) safrole.State {
	sealingKeySeries := safrole.TicketsOrKeys{}
	err := sealingKeySeries.SetValue(RandomTicketBodies(t))
	require.NoError(t, err)

	return safrole.State{
		NextValidators:    RandomValidatorsData(t),
		TicketAccumulator: RandomTickets(t),
		SealingKeySeries:  sealingKeySeries,
		RingCommitment:    testutils.RandomBandersnatchRingCommitment(t),
	}
}

func RandomSafroleStateWithEpochKeys(t *testing.T) safrole.State {
	sealingKeySeries := safrole.TicketsOrKeys{}
	err := sealingKeySeries.SetValue(RandomEpochKeys(t))
	require.NoError(t, err)

	return safrole.State{
		NextValidators:    RandomValidatorsData(t),
		TicketAccumulator: RandomTickets(t),
		SealingKeySeries:  sealingKeySeries,
		RingCommitment:    testutils.RandomBandersnatchRingCommitment(t),
	}
}

func RandomState(t *testing.T) State {
	services := make(service.ServiceState)
	for i := 0; i < 10; i++ {
		services[block.ServiceId(789)] = RandomServiceAccount(t)
	}

	return State{
		Services:                 services,
		PrivilegedServices:       RandomPrivilegedServices(),
		ValidatorState:           RandomValidatorState(t),
		EntropyPool:              RandomEntropyPool(t),
		CoreAuthorizersPool:      RandomCoreAuthorizersPool(t),
		PendingAuthorizersQueues: RandomPendingAuthorizersQueues(t),
		CoreAssignments:          RandomCoreAssignments(t),
		RecentBlocks:             []BlockState{RandomBlockState(t)},
		TimeslotIndex:            testutils.RandomTimeslot(),
		PastJudgements:           RandomJudgements(t),
		ValidatorStatistics:      RandomValidatorStatisticsState(),
		AccumulationQueue:        RandomAccumulationQueue(t),
		AccumulationHistory:      RandomAccumulationHistory(t),
	}
}

// DeserializeState deserializes the given map of crypto.Hash to byte slices into a State object. Not possible to restore the full state.
func DeserializeState(serializedState map[crypto.Hash][]byte) (State, error) {
	state := State{}

	// Helper function to deserialize individual fields
	deserializeField := func(key uint8, target interface{}) error {
		stateKey := generateStateKeyBasic(key)
		encodedValue, ok := serializedState[stateKey]
		if !ok {
			return errors.New("missing state key")
		}
		return jam.Unmarshal(encodedValue, target)
	}

	// Deserialize basic fields
	basicFields := []struct {
		key   uint8
		value interface{}
	}{
		{1, &state.CoreAuthorizersPool},
		{2, &state.PendingAuthorizersQueues},
		{3, &state.RecentBlocks},
		{6, &state.EntropyPool},
		{7, &state.ValidatorState.QueuedValidators},
		{8, &state.ValidatorState.CurrentValidators},
		{9, &state.ValidatorState.ArchivedValidators},
		{10, &state.CoreAssignments},
		{11, &state.TimeslotIndex},
		{12, &state.PrivilegedServices},
		{13, &state.ValidatorStatistics},
		{14, &state.AccumulationQueue},
		{15, &state.AccumulationHistory},
	}

	for _, field := range basicFields {
		if err := deserializeField(field.key, field.value); err != nil {
			return state, err
		}
	}

	// Deserialize SafroleState specific fields
	if err := deserializeSafroleState(&state, serializedState); err != nil {
		return state, err
	}

	// Deserialize Past Judgements
	if err := deserializeJudgements(&state, serializedState); err != nil {
		return state, err
	}

	// Deserialize Services
	if err := deserializeServices(&state, serializedState); err != nil {
		return state, err
	}

	return state, nil
}

func deserializeSafroleState(state *State, serializedState map[crypto.Hash][]byte) error {
	stateKey := generateStateKeyBasic(4)
	encodedSafroleState, ok := serializedState[stateKey]
	if !ok {
		return fmt.Errorf("missing the state key for safrole state %v", stateKey)
	}

	decodedSafroleState := safrole.State{}

	if err := jam.Unmarshal(encodedSafroleState, &decodedSafroleState); err != nil {
		return err
	}

	state.ValidatorState.SafroleState = decodedSafroleState

	return nil
}

func deserializeJudgements(state *State, serializedState map[crypto.Hash][]byte) error {
	stateKey := generateStateKeyBasic(5)
	encodedValue, ok := serializedState[stateKey]
	if !ok {
		return errors.New("missing PastJudgements key")
	}

	// Deserialize the combined Judgements fields
	var combined struct {
		GoodWorkReports     []crypto.Hash
		BadWorkReports      []crypto.Hash
		WonkyWorkReports    []crypto.Hash
		OffendingValidators []ed25519.PublicKey
	}
	if err := jam.Unmarshal(encodedValue, &combined); err != nil {
		return err
	}

	state.PastJudgements.GoodWorkReports = combined.GoodWorkReports
	state.PastJudgements.BadWorkReports = combined.BadWorkReports
	state.PastJudgements.WonkyWorkReports = combined.WonkyWorkReports
	state.PastJudgements.OffendingValidators = combined.OffendingValidators

	return nil
}

func deserializeServices(state *State, serializedState map[crypto.Hash][]byte) error {
	state.Services = make(service.ServiceState)

	// Iterate over serializedState and look for service entries (identified by prefix 255)
	for stateKey, encodedValue := range serializedState {
		// Check if this is a service account entry (state key starts with 255)
		if isServiceAccountKey(stateKey) {
			// Extract service ID from the key
			serviceId := extractServiceIdFromKey(stateKey)

			// Deserialize the combined fields (CodeHash, Balance, etc.)
			var combined struct {
				CodeHash               crypto.Hash
				Balance                uint64
				GasLimitForAccumulator uint64
				GasLimitOnTransfer     uint64
				FootprintSize          uint64
				FootprintItems         int
			}
			if err := jam.Unmarshal(encodedValue, &combined); err != nil {
				return err
			}

			// Create and populate the ServiceAccount from the deserialized data
			serviceAccount := service.ServiceAccount{
				CodeHash:               combined.CodeHash,
				Balance:                combined.Balance,
				GasLimitForAccumulator: combined.GasLimitForAccumulator,
				GasLimitOnTransfer:     combined.GasLimitOnTransfer,
			}

			// We cannot completely deserialize storage and preimage items. That's why they are not here.

			// Add the deserialized service account to the state
			state.Services[serviceId] = serviceAccount
		}
	}

	return nil
}

func isServiceAccountKey(stateKey crypto.Hash) bool {
	// Check if the first byte of the state key is 255 (which identifies service keys)
	return stateKey[0] == 255
}

func extractServiceIdFromKey(stateKey crypto.Hash) block.ServiceId {
	// Assuming that the service ID is embedded in bytes 1-4 of the key
	return block.ServiceId(binary.BigEndian.Uint32(stateKey[1:5]))
}
