package serialization

import (
	"crypto/ed25519"
	"testing"

	"github.com/eigerco/strawberry/internal/state"
	"github.com/eigerco/strawberry/internal/state/serialization/statekey"

	"github.com/stretchr/testify/require"

	"github.com/eigerco/strawberry/internal/block"
	"github.com/eigerco/strawberry/internal/common"
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/safrole"
	"github.com/eigerco/strawberry/internal/service"
	"github.com/eigerco/strawberry/internal/testutils"
	"github.com/eigerco/strawberry/internal/validator"
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

func RandomServiceAccount(t *testing.T, svcID block.ServiceId) service.ServiceAccount {
	preimageData := []byte("preimage data")
	sa := service.ServiceAccount{
		PreimageLookup:                 map[crypto.Hash][]byte{crypto.HashData(preimageData): preimageData},
		CodeHash:                       testutils.RandomHash(t),
		Balance:                        testutils.RandomUint64(),
		GasLimitForAccumulator:         testutils.RandomUint64(),
		GasLimitOnTransfer:             testutils.RandomUint64(),
		GratisStorageOffset:            testutils.RandomUint64(),
		CreationTimeslot:               testutils.RandomTimeslot(),
		MostRecentAccumulationTimeslot: testutils.RandomTimeslot(),
		ParentService:                  block.ServiceId(testutils.RandomUint32()),
	}

	// Insert a storage key.
	originalStorageKey := []byte("storage key")
	storageKey, err := statekey.NewStorage(svcID, originalStorageKey)
	require.NoError(t, err)
	sa.InsertStorage(storageKey, uint64(len(originalStorageKey)), []byte("storage value"))

	// Insert a preimage meta key.
	preimageMetaKey, err := statekey.NewPreimageMeta(svcID, crypto.HashData(preimageData), uint32(len(preimageData)))
	require.NoError(t, err)
	err = sa.InsertPreimageMeta(preimageMetaKey, uint64(len(preimageData)), service.PreimageHistoricalTimeslots{testutils.RandomTimeslot()})
	require.NoError(t, err)

	return sa
}

func RandomPrivilegedServices() service.PrivilegedServices {
	amountOfGasPerServiceId := map[block.ServiceId]uint64{
		block.ServiceId(123): 12344,
		block.ServiceId(234): 23455,
		block.ServiceId(345): 34566,
	}
	return service.PrivilegedServices{
		ManagerServiceId:        block.ServiceId(123),
		AssignedServiceIds:      [common.TotalNumberOfCores]block.ServiceId{234},
		DesignateServiceId:      block.ServiceId(345),
		AmountOfGasPerServiceId: amountOfGasPerServiceId,
	}
}

func RandomEntropyPool(t *testing.T) state.EntropyPool {
	return state.EntropyPool{testutils.RandomHash(t), testutils.RandomHash(t), testutils.RandomHash(t), testutils.RandomHash(t)}
}

func RandomCoreAuthorizersPool(t *testing.T) state.CoreAuthorizersPool {
	var pool state.CoreAuthorizersPool
	for i := range pool {
		for range state.MaxAuthorizersPerCore {
			pool[i] = append(pool[i], testutils.RandomHash(t))
		}
	}
	return pool
}

func RandomPendingAuthorizersQueues(t *testing.T) state.PendingAuthorizersQueues {
	var queue state.PendingAuthorizersQueues
	for i := range queue {
		for j := 0; j < state.PendingAuthorizersQueueSize; j++ {
			queue[i][j] = testutils.RandomHash(t)
		}
	}
	return queue
}

func RandomCoreAssignments(t *testing.T) state.CoreAssignments {
	var assignments state.CoreAssignments
	for i := range assignments {
		assignments[i] = &state.Assignment{
			WorkReport: &block.WorkReport{
				WorkPackageSpecification: block.WorkPackageSpecification{WorkPackageHash: testutils.RandomHash(t)},
				RefinementContext: block.RefinementContext{
					Anchor:                  block.RefinementContextAnchor{HeaderHash: testutils.RandomHash(t)},
					LookupAnchor:            block.RefinementContextLookupAnchor{HeaderHash: testutils.RandomHash(t), Timeslot: testutils.RandomTimeslot()},
					PrerequisiteWorkPackage: nil,
				},
				CoreIndex:         uint16(i),
				AuthorizerHash:    testutils.RandomHash(t),
				Trace:             []byte("output"),
				SegmentRootLookup: make(map[crypto.Hash]crypto.Hash),
				WorkResults:       []block.WorkResult{RandomWorkResult(t)},
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

func RandomAccumulationQueue(t *testing.T) state.AccumulationQueue {
	var queue state.AccumulationQueue
	for i := 0; i < len(queue); i++ {
		// For each timeslot, create a random slice of WorkReportWithUnAccumulatedDependencies
		numReports := testutils.RandomUint32()%5 + 1 // Random number of work reports (1-5)
		for j := 0; j < int(numReports); j++ {
			queue[i] = append(queue[i], state.WorkReportWithUnAccumulatedDependencies{
				WorkReport:   RandomWorkReport(t),
				Dependencies: RandomHashSet(t, 5), // Random set of crypto.Hash
			})
		}
	}
	return queue
}

func RandomAccumulationHistory(t *testing.T) state.AccumulationHistory {
	var history state.AccumulationHistory
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
		CoreIndex:         testutils.RandomUint16(),
		AuthorizerHash:    testutils.RandomHash(t),
		Trace:             []byte("random output"),
		SegmentRootLookup: make(map[crypto.Hash]crypto.Hash),
		WorkResults:       []block.WorkResult{RandomWorkResult(t)},
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

func RandomRecentHistory(t *testing.T) state.RecentHistory {
	workReportHashes := make(map[crypto.Hash]crypto.Hash)
	for i := uint16(0); i < common.TotalNumberOfCores; i++ {
		workReportHashes[testutils.RandomHash(t)] = testutils.RandomHash(t)
	}
	accumulationOutputLogHash := testutils.RandomHash(t)
	return state.RecentHistory{
		BlockHistory: []state.BlockState{
			{
				HeaderHash: testutils.RandomHash(t),
				StateRoot:  testutils.RandomHash(t),
				BeefyRoot:  testutils.RandomHash(t),
				Reported:   workReportHashes,
			},
		},
		AccumulationOutputLog: []*crypto.Hash{
			&accumulationOutputLogHash,
		},
	}
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
		NumOfTickets:                testutils.RandomUint32(),
		NumOfPreimages:              testutils.RandomUint32(),
		NumOfBytesAllPreimages:      testutils.RandomUint32(),
		NumOfGuaranteedReports:      testutils.RandomUint32(),
		NumOfAvailabilityAssurances: testutils.RandomUint32(),
	}
}

func RandomValidatorStatisticsState() validator.ActivityStatisticsState {
	return validator.ActivityStatisticsState{
		ValidatorsCurrent: [common.NumberOfValidators]validator.ValidatorStatistics{RandomValidatorStatistics(), RandomValidatorStatistics()},
		ValidatorsLast:    [common.NumberOfValidators]validator.ValidatorStatistics{RandomValidatorStatistics(), RandomValidatorStatistics()},
	}
}

func RandomJudgements(t *testing.T) state.Judgements {
	offendingValidators := make([]ed25519.PublicKey, 5)
	for i := range offendingValidators {
		offendingValidators[i] = testutils.RandomED25519PublicKey(t)
	}
	return state.Judgements{
		BadWorkReports:      []crypto.Hash{testutils.RandomHash(t)},
		GoodWorkReports:     []crypto.Hash{testutils.RandomHash(t)},
		WonkyWorkReports:    []crypto.Hash{testutils.RandomHash(t)},
		OffendingValidators: offendingValidators,
	}
}

func RandomSafroleStateWithTicketBodies(t *testing.T) safrole.State {
	sealingKeySeries := safrole.SealingKeys{}
	sealingKeySeries.Set(RandomTicketBodies(t))

	return safrole.State{
		NextValidators:    RandomValidatorsData(t),
		TicketAccumulator: RandomTickets(t),
		SealingKeySeries:  sealingKeySeries,
		RingCommitment:    testutils.RandomBandersnatchRingCommitment(t),
	}
}

func RandomSafroleStateWithEpochKeys(t *testing.T) safrole.State {
	sealingKeySeries := safrole.SealingKeys{}
	sealingKeySeries.Set(RandomEpochKeys(t))

	return safrole.State{
		NextValidators:    RandomValidatorsData(t),
		TicketAccumulator: RandomTickets(t),
		SealingKeySeries:  sealingKeySeries,
		RingCommitment:    testutils.RandomBandersnatchRingCommitment(t),
	}
}

func RandomAccumulationOutputLog(t *testing.T, maxSize int) state.AccumulationOutputLog {
	accumulationOutputLog := state.AccumulationOutputLog{}
	numEntries := testutils.RandomUint32()%uint32(maxSize) + 1
	for i := 0; i < int(numEntries); i++ {
		accumulationOutputLog = append(accumulationOutputLog, state.ServiceHashPair{
			ServiceId: block.ServiceId(testutils.RandomUint32()),
			Hash:      testutils.RandomHash(t),
		})
	}
	return accumulationOutputLog
}

func RandomState(t *testing.T) state.State {
	services := make(service.ServiceState)
	for i := 0; i < 10; i++ {
		// Use different service IDs for each iteration
		sID := block.ServiceId(uint32(i + 789))
		services[sID] = RandomServiceAccount(t, sID)
	}

	return state.State{
		Services:                 services,
		PrivilegedServices:       RandomPrivilegedServices(),
		ValidatorState:           RandomValidatorState(t),
		EntropyPool:              RandomEntropyPool(t),
		CoreAuthorizersPool:      RandomCoreAuthorizersPool(t),
		PendingAuthorizersQueues: RandomPendingAuthorizersQueues(t),
		CoreAssignments:          RandomCoreAssignments(t),
		RecentHistory:            RandomRecentHistory(t),
		TimeslotIndex:            testutils.RandomTimeslot(),
		PastJudgements:           RandomJudgements(t),
		ActivityStatistics:       RandomValidatorStatisticsState(),
		AccumulationQueue:        RandomAccumulationQueue(t),
		AccumulationHistory:      RandomAccumulationHistory(t),
		AccumulationOutputLog:    RandomAccumulationOutputLog(t, 10),
	}
}
