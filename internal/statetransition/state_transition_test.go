package statetransition

import (
	"testing"

	"github.com/eigerco/strawberry/internal/crypto/ed25519"

	"github.com/eigerco/strawberry/internal/disputing"
	"github.com/eigerco/strawberry/internal/service"
	"github.com/eigerco/strawberry/internal/state/serialization/statekey"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/eigerco/strawberry/internal/block"
	"github.com/eigerco/strawberry/internal/common"
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/jamtime"
	"github.com/eigerco/strawberry/internal/safrole"
	"github.com/eigerco/strawberry/internal/state"
	"github.com/eigerco/strawberry/internal/testutils"
	"github.com/eigerco/strawberry/internal/validator"
)

func TestCalculateNewTimeStateTransition(t *testing.T) {
	header := block.Header{
		TimeSlotIndex: 2,
	}
	newTimeState := CalculateNewTimeState(header)
	require.Equal(t, newTimeState, header.TimeSlotIndex)
}

func TestCalculateNewEntropyPoolWhenNewEpoch(t *testing.T) {
	entropyPool := [4]crypto.Hash{
		crypto.Hash(testutils.MustFromHex(t,
			"0xf164ce89b10488598cb295e4eef273fb8977722f4d6b2754b970ac77b45fa29b")),
		testutils.RandomHash(t),
		testutils.RandomHash(t),
		testutils.RandomHash(t),
	}

	newEntropyPool, err := calculateNewEntropyPool(jamtime.Timeslot(599),
		jamtime.Timeslot(600),
		crypto.BandersnatchOutputHash(testutils.MustFromHex(t,
			"0x92e69aed566b11bf02354c64e44235b79154207021b7db0f03ca62108f826f94")),
		entropyPool)
	require.NoError(t, err)
	assert.Equal(t, newEntropyPool[0], crypto.Hash(testutils.MustFromHex(t,
		"0x760612c571119ba1af27e99ad6c47b3905469f87cb0453e648df973d003f2160")))
	assert.Equal(t, entropyPool[2], newEntropyPool[3])
	assert.Equal(t, entropyPool[1], newEntropyPool[2])
	assert.Equal(t, entropyPool[0], newEntropyPool[1])
}

func TestCalculateNewEntropyPoolWhenNotNewEpoch(t *testing.T) {
	entropyPool := [4]crypto.Hash{
		crypto.Hash(testutils.MustFromHex(t,
			"0xf164ce89b10488598cb295e4eef273fb8977722f4d6b2754b970ac77b45fa29b")),
		testutils.RandomHash(t),
		testutils.RandomHash(t),
		testutils.RandomHash(t),
	}
	newEntropyPool, err := calculateNewEntropyPool(jamtime.Timeslot(600),
		jamtime.Timeslot(601),
		crypto.BandersnatchOutputHash(testutils.MustFromHex(t,
			"0x92e69aed566b11bf02354c64e44235b79154207021b7db0f03ca62108f826f94")),
		entropyPool)
	require.NoError(t, err)
	assert.Equal(t, newEntropyPool[0], crypto.Hash(testutils.MustFromHex(t,
		"0x760612c571119ba1af27e99ad6c47b3905469f87cb0453e648df973d003f2160")))
	assert.Equal(t, entropyPool[3], newEntropyPool[3])
	assert.Equal(t, entropyPool[2], newEntropyPool[2])
	assert.Equal(t, entropyPool[1], newEntropyPool[1])
}

func TestAddUniqueHash(t *testing.T) {
	slice := []crypto.Hash{{1}, {2}, {3}}

	newSlice := addUniqueHash(slice, crypto.Hash{2})
	assert.Len(t, newSlice, 3, "Slice length should remain 3 when adding existing hash")

	newSlice = addUniqueHash(slice, crypto.Hash{4})
	assert.Len(t, newSlice, 4, "Slice length should be 4 after adding new hash")
	assert.Equal(t, crypto.Hash{4}, newSlice[3], "Last element should be the newly added hash")
}

func TestAddUniqueEdPubKey(t *testing.T) {
	key1 := ed25519.PublicKey([]byte{1, 2, 3})
	key2 := ed25519.PublicKey([]byte{4, 5, 6})
	slice := []ed25519.PublicKey{key1}

	newSlice := addUniqueEdPubKey(slice, key1)
	assert.Len(t, newSlice, 1, "Slice length should remain 1 when adding existing key")

	newSlice = addUniqueEdPubKey(slice, key2)
	assert.Len(t, newSlice, 2, "Slice length should be 2 after adding new key")
	assert.Equal(t, key2, newSlice[1], "Last element should be the newly added key")
}

func TestCalculateIntermediateServiceState(t *testing.T) {
	preimageData := []byte{1, 2, 3}
	preimageHash := crypto.HashData(preimageData)
	preimageLength := service.PreimageLength(len(preimageData))
	newTimeslot := jamtime.Timeslot(100)

	preimages := block.PreimageExtrinsic{
		{
			ServiceIndex: 0,
			Data:         preimageData,
		},
	}

	k, err := statekey.NewPreimageMeta(0, preimageHash, uint32(preimageLength))
	require.NoError(t, err)

	// For a preimage to be considered solicited, the PreimageMeta entry must exist and be empty.
	serviceState := service.ServiceState{
		block.ServiceId(0): func() service.ServiceAccount {
			account := service.ServiceAccount{
				PreimageLookup: map[crypto.Hash][]byte{
					{4, 5, 6}: {7, 8, 9},
				},
			}

			err = account.InsertPreimageMeta(k, uint64(preimageLength), service.PreimageHistoricalTimeslots{})
			require.NoError(t, err)

			return account
		}(),
	}

	// Expected state: preimage is added to lookup and metadata updated with newTimeslot.
	expectedServiceState := service.ServiceState{
		block.ServiceId(0): func() service.ServiceAccount {
			account := service.ServiceAccount{
				PreimageLookup: map[crypto.Hash][]byte{
					{4, 5, 6}:    {7, 8, 9},
					preimageHash: preimageData,
				},
			}

			err := account.InsertPreimageMeta(k, uint64(preimageLength), service.PreimageHistoricalTimeslots{newTimeslot})
			require.NoError(t, err)

			return account
		}(),
	}

	newServiceState, err := CalculateNewServiceStateWithPreimages(preimages, serviceState, newTimeslot)
	require.NoError(t, err)
	require.Equal(t, expectedServiceState, newServiceState)
}

func TestCalculateIntermediateServiceStateEmptyPreimages(t *testing.T) {
	sa := service.ServiceAccount{
		PreimageLookup: map[crypto.Hash][]byte{
			{4, 5, 6}: {7, 8, 9},
		},
	}
	k, err := statekey.NewPreimageMeta(0, crypto.Hash{4, 5, 6}, uint32(3))
	require.NoError(t, err)

	err = sa.InsertPreimageMeta(k, uint64(3), service.PreimageHistoricalTimeslots{jamtime.Timeslot(50)})
	require.NoError(t, err)

	serviceState := service.ServiceState{
		block.ServiceId(0): sa,
	}

	expectedServiceState := serviceState

	newServiceState, err := CalculateNewServiceStateWithPreimages(block.PreimageExtrinsic{}, serviceState, jamtime.Timeslot(100))
	require.NoError(t, err)
	require.Equal(t, expectedServiceState, newServiceState)
}

func TestCalculateIntermediateServiceStateNonExistentService(t *testing.T) {
	preimageData := []byte{1, 2, 3}

	preimages := block.PreimageExtrinsic{
		{
			ServiceIndex: 1, // Non-existent service
			Data:         preimageData,
		},
	}

	sa := service.ServiceAccount{
		PreimageLookup: map[crypto.Hash][]byte{
			{4, 5, 6}: {7, 8, 9},
		},
	}
	k, err := statekey.NewPreimageMeta(0, crypto.Hash{4, 5, 6}, uint32(3))
	require.NoError(t, err)

	err = sa.InsertPreimageMeta(k, uint64(3), service.PreimageHistoricalTimeslots{jamtime.Timeslot(50)})
	require.NoError(t, err)

	// Since service 1 does not exist, preimageHasBeenSolicited will return false.
	serviceState := service.ServiceState{
		block.ServiceId(0): sa,
	}

	err = ValidatePreimages(preimages, serviceState)
	require.Error(t, err)
	require.Equal(t, "preimage unneeded", err.Error())
}

func TestCalculateIntermediateServiceStateMultiplePreimages(t *testing.T) {
	preimageData1 := []byte{1, 2, 3}
	preimageData2 := []byte{4, 5, 6}
	preimageHash1 := crypto.HashData(preimageData1)
	preimageHash2 := crypto.HashData(preimageData2)
	preimageLength1 := service.PreimageLength(len(preimageData1))
	preimageLength2 := service.PreimageLength(len(preimageData2))
	newTimeslot := jamtime.Timeslot(100)

	preimages := block.PreimageExtrinsic{
		{
			ServiceIndex: 0,
			Data:         preimageData1,
		},
		{
			ServiceIndex: 0,
			Data:         preimageData2,
		},
	}

	k1, err := statekey.NewPreimageMeta(0, preimageHash1, uint32(preimageLength1))
	require.NoError(t, err)

	k2, err := statekey.NewPreimageMeta(0, preimageHash2, uint32(preimageLength2))
	require.NoError(t, err)

	account := service.NewServiceAccount()
	err = account.InsertPreimageMeta(k1, uint64(preimageLength1), service.PreimageHistoricalTimeslots{})
	require.NoError(t, err)

	err = account.InsertPreimageMeta(k2, uint64(preimageLength2), service.PreimageHistoricalTimeslots{})
	require.NoError(t, err)

	// For both preimages to be solicited, add empty metadata entries.
	serviceState := service.ServiceState{
		block.ServiceId(0): account,
	}

	expectedServiceState := service.ServiceState{
		block.ServiceId(0): func() service.ServiceAccount {
			// Marshal historical timeslot with the newTimeslot
			sa := service.NewServiceAccount()
			err = sa.InsertPreimageMeta(k1, uint64(preimageLength1), service.PreimageHistoricalTimeslots{newTimeslot})
			require.NoError(t, err)

			err = sa.InsertPreimageMeta(k2, uint64(preimageLength2), service.PreimageHistoricalTimeslots{newTimeslot})
			require.NoError(t, err)

			sa.PreimageLookup = map[crypto.Hash][]byte{
				preimageHash1: preimageData1,
				preimageHash2: preimageData2,
			}

			return sa
		}(),
	}

	newServiceState, err := CalculateNewServiceStateWithPreimages(preimages, serviceState, newTimeslot)
	require.NoError(t, err)
	require.Equal(t, expectedServiceState, newServiceState)
}

func TestCalculateIntermediateServiceStateExistingPreimage(t *testing.T) {
	existingPreimageData := []byte{1, 2, 3}
	existingPreimageHash := crypto.HashData(existingPreimageData)
	newPreimageData := []byte{4, 5, 6}

	preimages := block.PreimageExtrinsic{
		{
			// The preimage already exists in the lookup, so it is not solicited.
			ServiceIndex: 0,
			Data:         existingPreimageData,
		},
		{
			ServiceIndex: 0,
			Data:         newPreimageData,
		},
	}

	sa := service.ServiceAccount{
		PreimageLookup: map[crypto.Hash][]byte{
			existingPreimageHash: existingPreimageData,
		},
	}
	// New preimage is solicited.
	k, err := statekey.NewPreimageMeta(0, crypto.HashData(newPreimageData), uint32(len(existingPreimageData)))
	require.NoError(t, err)

	err = sa.InsertPreimageMeta(k, uint64(len(newPreimageData)), service.PreimageHistoricalTimeslots{})
	require.NoError(t, err)

	// Existing preimage metadata is non-empty (already provided).
	k, err = statekey.NewPreimageMeta(0, existingPreimageHash, uint32(len(existingPreimageData)))
	require.NoError(t, err)

	err = sa.InsertPreimageMeta(k, uint64(len(existingPreimageHash)), service.PreimageHistoricalTimeslots{jamtime.Timeslot(50)})
	require.NoError(t, err)

	// In serviceState, mark the new preimage as solicited but the existing one is already provided.
	serviceState := service.ServiceState{
		block.ServiceId(0): sa,
	}

	err = ValidatePreimages(preimages, serviceState)
	require.Error(t, err)
	require.Equal(t, "preimage unneeded", err.Error())
}

func TestCalculateIntermediateServiceStateExistingMetadata(t *testing.T) {
	preimageData := []byte{1, 2, 3}
	preimageHash := crypto.HashData(preimageData)

	preimages := block.PreimageExtrinsic{
		{
			ServiceIndex: 0,
			Data:         preimageData,
		},
	}

	sa := service.ServiceAccount{
		PreimageLookup: map[crypto.Hash][]byte{},
	}
	k, err := statekey.NewPreimageMeta(0, preimageHash, uint32(len(preimageData)))
	require.NoError(t, err)

	err = sa.InsertPreimageMeta(k, uint64(len(preimageData)), service.PreimageHistoricalTimeslots{jamtime.Timeslot(50)})
	require.NoError(t, err)

	// The metadata already exists with a non-empty slice, so the preimage is not solicited.
	serviceState := service.ServiceState{
		block.ServiceId(0): sa,
	}

	err = ValidatePreimages(preimages, serviceState)
	require.Error(t, err)
	require.Equal(t, "preimage unneeded", err.Error())
}

func TestCalculateIntermediateCoreAssignmentsFromExtrinsics(t *testing.T) {
	// Create WorkReports with known hashes
	workReport1 := block.WorkReport{CoreIndex: 0}
	workReport2 := block.WorkReport{CoreIndex: 1}

	hash1, _ := workReport1.Hash()
	hash2, _ := workReport2.Hash()

	coreAssignments := state.CoreAssignments{
		{WorkReport: workReport1},
		{WorkReport: workReport2},
	}

	disputes := block.DisputeExtrinsic{
		Verdicts: []block.Verdict{
			createVerdictWithJudgments(hash1, common.ValidatorsSuperMajority-1),
			createVerdictWithJudgments(hash2, common.ValidatorsSuperMajority),
		},
	}

	expectedAssignments := state.CoreAssignments{
		nil, // Cleared due to less than super majority
		{WorkReport: workReport2},
	}

	newAssignments := disputing.CalculateIntermediateCoreAssignmentsFromExtrinsics(disputes, coreAssignments)
	require.Equal(t, expectedAssignments, newAssignments)
}

func TestCalculateNewCoreAuthorizations(t *testing.T) {
	t.Run("add new authorizer to empty pool", func(t *testing.T) {
		header := block.Header{
			TimeSlotIndex: 1,
		}
		pendingAuths := state.PendingAuthorizersQueues{}
		currentAuths := state.CoreAuthorizersPool{}

		// Set up a pending authorizer for core 0
		newAuth := testutils.RandomHash(t)
		pendingAuths[0][1] = newAuth // At index 1 (matching TimeSlotIndex)

		newAuths := CalculateNewCoreAuthorizations(header, block.GuaranteesExtrinsic{}, pendingAuths, currentAuths)

		require.Len(t, newAuths[0], 1)
		assert.Equal(t, newAuth, newAuths[0][0])
	})

	t.Run("remove used authorizer and add new one", func(t *testing.T) {
		header := block.Header{
			TimeSlotIndex: 1,
		}

		// Create a guarantee that uses an authorizer
		usedAuth := testutils.RandomHash(t)
		workReport := block.WorkReport{
			CoreIndex:      0,
			AuthorizerHash: usedAuth,
		}
		guarantees := block.GuaranteesExtrinsic{
			Guarantees: []block.Guarantee{
				{WorkReport: workReport},
			},
		}

		// Set up current authorizations with the used authorizer
		currentAuths := state.CoreAuthorizersPool{}
		currentAuths[0] = []crypto.Hash{usedAuth}

		// Set up pending authorizations with new authorizer
		pendingAuths := state.PendingAuthorizersQueues{}
		newAuth := testutils.RandomHash(t)
		pendingAuths[0][1] = newAuth // At index 1 (matching TimeSlotIndex)

		newAuths := CalculateNewCoreAuthorizations(header, guarantees, pendingAuths, currentAuths)

		require.Len(t, newAuths[0], 1)
		assert.Equal(t, newAuth, newAuths[0][0])
		assert.NotContains(t, newAuths[0], usedAuth)
	})

	t.Run("left-shift authorizers when no guarantee used", func(t *testing.T) {
		header := block.Header{
			TimeSlotIndex: 1,
		}

		// Set up current authorizations with multiple authorizers
		currentAuths := state.CoreAuthorizersPool{}
		auth1 := testutils.RandomHash(t)
		auth2 := testutils.RandomHash(t)
		currentAuths[0] = []crypto.Hash{auth1, auth2}

		// Set up pending authorizations with new authorizer
		pendingAuths := state.PendingAuthorizersQueues{}
		newAuth := testutils.RandomHash(t)
		pendingAuths[0][1] = newAuth

		newAuths := CalculateNewCoreAuthorizations(header, block.GuaranteesExtrinsic{}, pendingAuths, currentAuths)

		// Check that auth1 was removed (left-shift) and newAuth was added
		require.Len(t, newAuths[0], 2)
		assert.Equal(t, auth2, newAuths[0][0], "First authorizer should be auth2 after left-shift")
		assert.Equal(t, newAuth, newAuths[0][1], "Second authorizer should be the new one")
		assert.NotContains(t, newAuths[0], auth1, "auth1 should be removed by left-shift")
	})

	t.Run("maintain max size limit", func(t *testing.T) {
		header := block.Header{
			TimeSlotIndex: 1,
		}

		// Fill current authorizations to max size
		currentAuths := state.CoreAuthorizersPool{}
		for i := 0; i < state.MaxAuthorizersPerCore; i++ {
			currentAuths[0] = append(currentAuths[0], testutils.RandomHash(t))
		}

		// Set up new pending authorizer
		pendingAuths := state.PendingAuthorizersQueues{}
		newAuth := testutils.RandomHash(t)
		pendingAuths[0][1] = newAuth

		newAuths := CalculateNewCoreAuthorizations(header, block.GuaranteesExtrinsic{}, pendingAuths, currentAuths)

		// Check that size limit is maintained and both oldest auth and left-shifted auth were removed
		require.Len(t, newAuths[0], state.MaxAuthorizersPerCore)
		assert.Equal(t, newAuth, newAuths[0][state.MaxAuthorizersPerCore-1])
		assert.NotEqual(t, currentAuths[0][0], newAuths[0][0], "First auth should be removed")
		assert.Equal(t, currentAuths[0][1], newAuths[0][0], "Second auth should be first now due to left-shift")
	})

	t.Run("handle empty pending authorization", func(t *testing.T) {
		header := block.Header{
			TimeSlotIndex: 1,
		}

		currentAuths := state.CoreAuthorizersPool{}
		auth1 := testutils.RandomHash(t)
		auth2 := testutils.RandomHash(t)
		currentAuths[0] = []crypto.Hash{auth1, auth2}

		// Empty pending authorizations
		pendingAuths := state.PendingAuthorizersQueues{}

		newAuths := CalculateNewCoreAuthorizations(header, block.GuaranteesExtrinsic{}, pendingAuths, currentAuths)

		// Should left-shift existing authorizations when no new auth is available
		require.Len(t, newAuths[0], 1)
		assert.Equal(t, auth2, newAuths[0][0], "Only second auth should remain after left-shift")
		assert.NotContains(t, newAuths[0], auth1, "First auth should be removed by left-shift")
	})

	t.Run("no left-shift when guarantee removes authorizer", func(t *testing.T) {
		header := block.Header{
			TimeSlotIndex: 1,
		}

		// Set up current authorizations
		currentAuths := state.CoreAuthorizersPool{}
		auth1 := testutils.RandomHash(t)
		auth2 := testutils.RandomHash(t)
		currentAuths[0] = []crypto.Hash{auth1, auth2}

		// Create a guarantee that uses the first authorizer
		workReport := block.WorkReport{
			CoreIndex:      0,
			AuthorizerHash: auth1,
		}
		guarantees := block.GuaranteesExtrinsic{
			Guarantees: []block.Guarantee{
				{WorkReport: workReport},
			},
		}

		// Set up new pending authorizer
		pendingAuths := state.PendingAuthorizersQueues{}
		newAuth := testutils.RandomHash(t)
		pendingAuths[0][1] = newAuth

		newAuths := CalculateNewCoreAuthorizations(header, guarantees, pendingAuths, currentAuths)

		// Check that only the used authorizer was removed (no left-shift) and new auth was added
		require.Len(t, newAuths[0], 2)
		assert.Equal(t, auth2, newAuths[0][0], "Second auth should remain in first position")
		assert.Equal(t, newAuth, newAuths[0][1], "New auth should be added at the end")
		assert.NotContains(t, newAuths[0], auth1, "Used auth should be removed")
	})

	t.Run("handle multiple cores", func(t *testing.T) {
		header := block.Header{
			TimeSlotIndex: 1,
		}

		// Set up authorizations for two cores
		currentAuths := state.CoreAuthorizersPool{}
		auth0_1 := testutils.RandomHash(t)
		auth0_2 := testutils.RandomHash(t)
		auth1_1 := testutils.RandomHash(t)
		auth1_2 := testutils.RandomHash(t)
		currentAuths[0] = []crypto.Hash{auth0_1, auth0_2}
		currentAuths[1] = []crypto.Hash{auth1_1, auth1_2}

		// Create a guarantee that uses an authorizer for core 1 only
		workReport := block.WorkReport{
			CoreIndex:      1,
			AuthorizerHash: auth1_1,
		}
		guarantees := block.GuaranteesExtrinsic{
			Guarantees: []block.Guarantee{
				{WorkReport: workReport},
			},
		}

		// Set up new pending authorizations
		pendingAuths := state.PendingAuthorizersQueues{}
		newAuth0 := testutils.RandomHash(t)
		newAuth1 := testutils.RandomHash(t)
		pendingAuths[0][1] = newAuth0
		pendingAuths[1][1] = newAuth1

		newAuths := CalculateNewCoreAuthorizations(header, guarantees, pendingAuths, currentAuths)

		// Core 0: Should left-shift (no guarantee)
		require.Len(t, newAuths[0], 2)
		assert.Equal(t, auth0_2, newAuths[0][0], "Core 0: First auth should be removed by left-shift")
		assert.Equal(t, newAuth0, newAuths[0][1], "Core 0: New auth should be added")
		assert.NotContains(t, newAuths[0], auth0_1, "Core 0: Original first auth should be removed")

		// Core 1: Should remove used auth (no left-shift)
		require.Len(t, newAuths[1], 2)
		assert.Equal(t, auth1_2, newAuths[1][0], "Core 1: Second auth should remain")
		assert.Equal(t, newAuth1, newAuths[1][1], "Core 1: New auth should be added")
		assert.NotContains(t, newAuths[1], auth1_1, "Core 1: Used auth should be removed")
	})
}

// Currently tests the validator statistics portion of CalculateNewActivityStatistics.
func TestCalculateNewActivityStatisticsForValidatorStatisticsOnly(t *testing.T) {
	t.Run("new epoch transition", func(t *testing.T) {
		// Initial state with some existing stats
		initialStats := validator.ActivityStatisticsState{
			ValidatorsLast: [common.NumberOfValidators]validator.ValidatorStatistics{
				0: {NumOfBlocks: 5},
				1: {NumOfTickets: 3},
			},
			ValidatorsCurrent: [common.NumberOfValidators]validator.ValidatorStatistics{
				0: {NumOfBlocks: 10},
				1: {NumOfTickets: 6},
			},
		}

		blk := block.Block{
			Header: block.Header{
				TimeSlotIndex:    jamtime.Timeslot(600), // First slot in new epoch
				BlockAuthorIndex: 2,
			},
		}

		newStats := CalculateNewActivityStatistics(blk, jamtime.Timeslot(599), initialStats, make(crypto.ED25519PublicKeySet),
			safrole.ValidatorsData{}, []block.WorkReport{}, AccumulationStats{})

		// Check that stats were rotated correctly
		assert.Equal(t, uint32(10), newStats.ValidatorsLast[0].NumOfBlocks, "Previous current stats should become history")
		assert.Equal(t, uint32(6), newStats.ValidatorsLast[1].NumOfTickets, "Previous current stats should become history")
		assert.Equal(t, uint32(0), newStats.ValidatorsCurrent[0].NumOfBlocks, "Current stats should be reset")
		assert.Equal(t, uint32(0), newStats.ValidatorsCurrent[1].NumOfTickets, "Current stats should be reset")
	})

	t.Run("block author statistics", func(t *testing.T) {
		initialStats := validator.ActivityStatisticsState{
			ValidatorsCurrent: [common.NumberOfValidators]validator.ValidatorStatistics{}, // Current epoch stats
		}

		blk := block.Block{
			Header: block.Header{
				TimeSlotIndex:    jamtime.Timeslot(5),
				BlockAuthorIndex: 1,
			},
			Extrinsic: block.Extrinsic{
				ET: block.TicketExtrinsic{
					TicketProofs: []block.TicketProof{{}, {}, {}}, // 3 tickets
				},
				EP: block.PreimageExtrinsic{
					{Data: []byte("test1")},
					{Data: []byte("test2")},
				},
			},
		}

		newStats := CalculateNewActivityStatistics(blk, jamtime.Timeslot(5), initialStats, make(crypto.ED25519PublicKeySet),
			safrole.ValidatorsData{}, []block.WorkReport{}, AccumulationStats{})

		// Check block author stats
		assert.Equal(t, uint32(1), newStats.ValidatorsCurrent[1].NumOfBlocks, "Block count should increment")
		assert.Equal(t, uint32(3), newStats.ValidatorsCurrent[1].NumOfTickets, "Ticket count should match")
		assert.Equal(t, uint32(2), newStats.ValidatorsCurrent[1].NumOfPreimages, "Preimage count should match")
		assert.Equal(t, uint32(10), newStats.ValidatorsCurrent[1].NumOfBytesAllPreimages, "Preimage bytes should match")

		// Check non-author stats remained zero
		assert.Equal(t, uint32(0), newStats.ValidatorsCurrent[0].NumOfBlocks, "Non-author stats should remain zero")
	})

	t.Run("guarantees and assurances", func(t *testing.T) {
		initialStats := validator.ActivityStatisticsState{
			ValidatorsCurrent: [common.NumberOfValidators]validator.ValidatorStatistics{}, // Current epoch stats
		}

		blk := block.Block{
			Header: block.Header{
				TimeSlotIndex: jamtime.Timeslot(5),
			},
			Extrinsic: block.Extrinsic{
				EG: block.GuaranteesExtrinsic{
					Guarantees: []block.Guarantee{
						{
							Credentials: []block.CredentialSignature{
								{ValidatorIndex: 0},
								{ValidatorIndex: 1},
							},
						},
						{
							Credentials: []block.CredentialSignature{
								{ValidatorIndex: 0},
							},
						},
					},
				},
				EA: block.AssurancesExtrinsic{
					{ValidatorIndex: 0},
					{ValidatorIndex: 1},
				},
			},
		}
		ed25519key1 := testutils.RandomED25519PublicKey(t)
		ed25519key2 := testutils.RandomED25519PublicKey(t)
		reporters := make(crypto.ED25519PublicKeySet)
		reporters.Add(ed25519key1)
		reporters.Add(ed25519key2)
		newStats := CalculateNewActivityStatistics(blk, jamtime.Timeslot(5), initialStats, reporters, safrole.ValidatorsData{{Ed25519: ed25519key1}, {Ed25519: ed25519key2}},
			[]block.WorkReport{}, AccumulationStats{})

		// Check guarantees and assurances
		assert.Equal(t, uint32(1), newStats.ValidatorsCurrent[0].NumOfGuaranteedReports, "Should count all guarantees for validator 0")
		assert.Equal(t, uint32(1), newStats.ValidatorsCurrent[1].NumOfGuaranteedReports, "Should count all guarantees for validator 1")
		assert.Equal(t, uint32(1), newStats.ValidatorsCurrent[0].NumOfAvailabilityAssurances, "Should count assurance for validator 0")
		assert.Equal(t, uint32(1), newStats.ValidatorsCurrent[1].NumOfAvailabilityAssurances, "Should count assurance for validator 1")
	})

	t.Run("full block processing", func(t *testing.T) {
		initialStats := validator.ActivityStatisticsState{
			ValidatorsCurrent: [common.NumberOfValidators]validator.ValidatorStatistics{
				1: {
					NumOfBlocks:                 5,
					NumOfTickets:                10,
					NumOfPreimages:              2,
					NumOfBytesAllPreimages:      100,
					NumOfGuaranteedReports:      3,
					NumOfAvailabilityAssurances: 2,
				},
			},
		}

		blk := block.Block{
			Header: block.Header{
				TimeSlotIndex:    jamtime.Timeslot(5),
				BlockAuthorIndex: 1,
			},
			Extrinsic: block.Extrinsic{
				ET: block.TicketExtrinsic{
					TicketProofs: []block.TicketProof{{}, {}}, // 2 tickets
				},
				EP: block.PreimageExtrinsic{
					{Data: []byte("test")}, // 4 bytes
				},
				EG: block.GuaranteesExtrinsic{
					Guarantees: []block.Guarantee{
						{
							Credentials: []block.CredentialSignature{
								{ValidatorIndex: 1},
							},
						},
					},
				},
				EA: block.AssurancesExtrinsic{
					{ValidatorIndex: 1},
				},
			},
		}

		ed25519key1 := testutils.RandomED25519PublicKey(t)
		ed25519key2 := testutils.RandomED25519PublicKey(t)
		reporters := make(crypto.ED25519PublicKeySet)
		reporters.Add(ed25519key1)
		reporters.Add(ed25519key2)
		newStats := CalculateNewActivityStatistics(blk, jamtime.Timeslot(5), initialStats, reporters, safrole.ValidatorsData{{Ed25519: ed25519key1}, {Ed25519: ed25519key2}},
			[]block.WorkReport{}, AccumulationStats{})

		expected := validator.ValidatorStatistics{
			NumOfBlocks:                 6,
			NumOfTickets:                12,
			NumOfPreimages:              3,
			NumOfBytesAllPreimages:      104,
			NumOfGuaranteedReports:      4,
			NumOfAvailabilityAssurances: 3,
		}

		assert.Equal(t, expected, newStats.ValidatorsCurrent[1], "All statistics should be updated correctly")
	})
}
func TestCalculateNewCoreStatistics(t *testing.T) {
	bitfieldCore0and1 := [block.AvailBitfieldBytes]byte{}
	bitfieldCore0and1[0] = 0x03

	testCases := []struct {
		name              string
		block             block.Block
		availableReports  []block.WorkReport
		expectedCoreStats [common.TotalNumberOfCores]validator.CoreStatistics
	}{
		{
			name:              "empty block, no available reports",
			block:             block.Block{},
			availableReports:  []block.WorkReport{},
			expectedCoreStats: [common.TotalNumberOfCores]validator.CoreStatistics{},
		},
		{
			name: "reports being made available",
			block: block.Block{
				Extrinsic: block.Extrinsic{
					EA: block.AssurancesExtrinsic{
						{Bitfield: bitfieldCore0and1},
						{Bitfield: bitfieldCore0and1},
						{Bitfield: bitfieldCore0and1},
						{Bitfield: bitfieldCore0and1},
						{Bitfield: bitfieldCore0and1},
						{Bitfield: bitfieldCore0and1},
					},
				},
			},
			availableReports: []block.WorkReport{
				{
					CoreIndex: 0,
					AvailabilitySpecification: block.AvailabilitySpecification{
						AuditableWorkBundleLength: 8649,
						SegmentCount:              2,
					},
				},
				{
					CoreIndex: 1,
					AvailabilitySpecification: block.AvailabilitySpecification{
						AuditableWorkBundleLength: 335,
						SegmentCount:              0,
					},
				},
			},
			expectedCoreStats: [common.TotalNumberOfCores]validator.CoreStatistics{
				0: {
					DALoad:     20961,
					Popularity: 6,
				},
				1: {
					DALoad:     335,
					Popularity: 6,
				},
			},
		},
		{
			name: "new reports",
			block: block.Block{
				Extrinsic: block.Extrinsic{
					EG: block.GuaranteesExtrinsic{
						Guarantees: []block.Guarantee{
							{
								WorkReport: block.WorkReport{
									CoreIndex: 0,
									AvailabilitySpecification: block.AvailabilitySpecification{
										AuditableWorkBundleLength: 17180,
										SegmentCount:              3,
									},

									WorkDigests: []block.WorkDigest{
										{
											GasUsed:               821,
											SegmentsImportedCount: 8,
											SegmentsExportedCount: 17,
											ExtrinsicCount:        8,
											ExtrinsicSize:         1526,
										},
									},
								},
							},
							{
								WorkReport: block.WorkReport{
									CoreIndex: 1,
									AvailabilitySpecification: block.AvailabilitySpecification{
										AuditableWorkBundleLength: 12487,
										SegmentCount:              3,
									},

									WorkDigests: []block.WorkDigest{
										{
											GasUsed:               697,
											SegmentsImportedCount: 1,
											SegmentsExportedCount: 18,
											ExtrinsicCount:        3,
											ExtrinsicSize:         1926,
										},
									},
								},
							},
						},
					},
				},
			},
			availableReports: []block.WorkReport{},
			expectedCoreStats: [common.TotalNumberOfCores]validator.CoreStatistics{
				0: {
					GasUsed:        821,
					Imports:        8,
					Exports:        17,
					ExtrinsicSize:  1526,
					ExtrinsicCount: 8,
					BundleSize:     17180,
				},
				1: {
					GasUsed:        697,
					Imports:        1,
					Exports:        18,
					ExtrinsicSize:  1926,
					ExtrinsicCount: 3,
					BundleSize:     12487,
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			newCoreStats := CalculateNewCoreStatistics(tc.block, [common.TotalNumberOfCores]validator.CoreStatistics{}, tc.availableReports)
			require.Equal(t, tc.expectedCoreStats, newCoreStats)
		})
	}
}

func TestCalculateNewServiceStatistics(t *testing.T) {
	testCases := []struct {
		name                 string
		block                block.Block
		accumulationStats    AccumulationStats
		expectedServiceStats validator.ServiceStatistics
	}{
		{
			name:                 "empty block",
			block:                block.Block{},
			expectedServiceStats: validator.ServiceStatistics{},
		},
		{
			name: "preimages",
			block: block.Block{
				Header: block.Header{
					TimeSlotIndex:    jamtime.Timeslot(5),
					BlockAuthorIndex: 1,
				},
				Extrinsic: block.Extrinsic{
					EP: block.PreimageExtrinsic{
						{
							ServiceIndex: 1,
							Data:         []byte("test1"),
						},
						{
							ServiceIndex: 1,
							Data:         []byte("test2"),
						},
					},
				},
			},
			expectedServiceStats: validator.ServiceStatistics{
				1: {
					ProvidedCount: 2,
					ProvidedSize:  10,
				},
			},
		},
		{
			name: "reports",
			block: block.Block{
				Extrinsic: block.Extrinsic{
					EG: block.GuaranteesExtrinsic{
						Guarantees: []block.Guarantee{
							{
								WorkReport: block.WorkReport{
									WorkDigests: []block.WorkDigest{
										{
											ServiceId:             1,
											GasUsed:               821,
											SegmentsImportedCount: 8,
											SegmentsExportedCount: 17,
											ExtrinsicCount:        8,
											ExtrinsicSize:         1526,
										},
									},
								},
							},
							{
								WorkReport: block.WorkReport{
									WorkDigests: []block.WorkDigest{
										{
											ServiceId:             1,
											GasUsed:               697,
											SegmentsImportedCount: 1,
											SegmentsExportedCount: 18,
											ExtrinsicCount:        3,
											ExtrinsicSize:         1926,
										},
									},
								},
							},
						},
					},
				},
			},
			expectedServiceStats: validator.ServiceStatistics{
				1: {
					RefinementCount:   2,
					RefinementGasUsed: 1518,
					Imports:           9,
					Exports:           35,
					ExtrinsicSize:     3452,
					ExtrinsicCount:    11,
				},
			},
		},
		{
			name:  "accumulation and transfer stats",
			block: block.Block{},
			accumulationStats: AccumulationStats{
				1: {
					AccumulateGasUsed: 1000,
					AccumulateCount:   1,
				},
				2: {
					AccumulateGasUsed: 2000,
					AccumulateCount:   2,
				},
			},
			expectedServiceStats: validator.ServiceStatistics{
				1: {
					AccumulateCount:   1,
					AccumulateGasUsed: 1000,
				},
				2: {
					AccumulateCount:   2,
					AccumulateGasUsed: 2000,
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			newServiceStats := CalculateNewServiceStatistics(tc.block, tc.accumulationStats)
			require.Equal(t, tc.expectedServiceStats, newServiceStats)
		})
	}
}

func createVerdictWithJudgments(reportHash crypto.Hash, positiveJudgments uint16) block.Verdict {
	var judgments [common.ValidatorsSuperMajority]block.Judgement
	for i := uint16(0); i < positiveJudgments; i++ {
		judgments[i] = block.Judgement{
			IsValid:        i < positiveJudgments,
			ValidatorIndex: i,
		}
	}
	return block.Verdict{
		ReportHash: reportHash,
		Judgements: judgments,
	}
}

func TestDedupePreimage(t *testing.T) {
	tests := []struct {
		name     string
		input    []block.Preimage
		expected []block.Preimage
	}{{
		name: "no duplicates",
		input: []block.Preimage{{
			ServiceIndex: 1,
			Data:         []byte("test1"),
		}, {
			ServiceIndex: 2,
			Data:         []byte("test1"),
		}, {
			ServiceIndex: 2,
			Data:         []byte("test2"),
		}},
		expected: []block.Preimage{{
			ServiceIndex: 1,
			Data:         []byte("test1"),
		}, {
			ServiceIndex: 2,
			Data:         []byte("test1"),
		}, {
			ServiceIndex: 2,
			Data:         []byte("test2"),
		}},
	}, {
		name: "one duplicate",
		input: []block.Preimage{{
			ServiceIndex: 1,
			Data:         []byte("test1"),
		}, {
			ServiceIndex: 1,
			Data:         []byte("test1"),
		}},
		expected: []block.Preimage{{
			ServiceIndex: 1,
			Data:         []byte("test1"),
		}},
	}, {
		name: "two duplicates",
		input: []block.Preimage{{
			ServiceIndex: 2,
			Data:         []byte("test123"),
		}, {
			ServiceIndex: 2,
			Data:         []byte("test123"),
		}, {
			ServiceIndex: 2,
			Data:         []byte("test123"),
		}},
		expected: []block.Preimage{{
			ServiceIndex: 2,
			Data:         []byte("test123"),
		}},
	}}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, dedupePreimages(tc.input))
		})
	}
}
