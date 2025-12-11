//go:build integration

package integration

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/eigerco/strawberry/internal/state/serialization/statekey"
	"github.com/eigerco/strawberry/internal/statetransition"
	"github.com/eigerco/strawberry/internal/store"
	"github.com/eigerco/strawberry/pkg/db/pebble"

	"github.com/stretchr/testify/require"

	"github.com/eigerco/strawberry/internal/block"
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/jamtime"
	"github.com/eigerco/strawberry/internal/service"
	jsonutils "github.com/eigerco/strawberry/internal/testutils/json"
)

func ReadPreimageJSONFile(filename string) (*PreimageTestVector, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %v", err)
	}
	defer file.Close()

	bytes, err := io.ReadAll(file)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %v", err)
	}

	var data PreimageTestVector
	if err := json.Unmarshal(bytes, &data); err != nil {
		return nil, fmt.Errorf("failed to unmarshal JSON: %v", err)
	}

	return &data, nil
}

// PreimageTestVector represents the JSON structure of a preimage test vector
type PreimageTestVector struct {
	Input     InputData     `json:"input"`
	PreState  PreimageState `json:"pre_state"`
	Output    OutputData    `json:"output"`
	PostState PreimageState `json:"post_state"`
}

// InputData represents the input for the preimage test
type InputData struct {
	Preimages []PreimageItem `json:"preimages"`
	Slot      uint64         `json:"slot"`
}

// PreimageItem represents a preimage in the input
type PreimageItem struct {
	Requester uint32 `json:"requester"`
	Blob      string `json:"blob"`
}

// PreimageState represents the state in the test vector
type PreimageState struct {
	Accounts          []AccountData               `json:"accounts"`
	ServiceStatistics jsonutils.ServiceStatistics `json:"statistics"`
}

// AccountData represents account data in state
type AccountData struct {
	ID   uint64       `json:"id"`
	Data ServiceState `json:"data"`
}

// ServiceState represents the service state in account data
type ServiceState struct {
	Preimages  []PreimageData       `json:"preimages"`
	LookupMeta []PreimageLookupMeta `json:"lookup_meta"`
}

// PreimageData represents a preimage in service state
type PreimageData struct {
	Hash string `json:"hash"`
	Blob string `json:"blob"`
}

// PreimageLookupMeta represents preimage metadata
type PreimageLookupMeta struct {
	Key   PreimageMetaKey `json:"key"`
	Value []uint64        `json:"value"`
}

// PreimageMetaKey represents the key for preimage metadata
type PreimageMetaKey struct {
	Hash   string `json:"hash"`
	Length uint32 `json:"length"`
}

// OutputData represents the expected output
type OutputData struct {
	Ok  interface{} `json:"ok"`
	Err string      `json:"err"`
}

func TestPreimage(t *testing.T) {
	files, err := os.ReadDir(fmt.Sprintf("vectors/preimages/%s", vectorsType))
	require.NoError(t, err, "failed to read directory: vectors/preimages/%s", vectorsType)

	db, err := pebble.NewKVStore()
	require.NoError(t, err)

	chain := store.NewChain(db)
	defer chain.Close()

	for _, file := range files {
		if !strings.HasSuffix(file.Name(), ".json") {
			continue
		}

		t.Run(file.Name(), func(t *testing.T) {

			filePath := fmt.Sprintf("vectors/preimages/%s/%s", vectorsType, file.Name())
			data, err := ReadPreimageJSONFile(filePath)
			require.NoError(t, err, "failed to read JSON file: %s", filePath)

			preServiceState := mapServiceState(t, data.PreState)
			preimages := mapPreimages(t, data.Input.Preimages)

			newTimeSlot := jamtime.Timeslot(data.Input.Slot)
			err = statetransition.ValidatePreimages(preimages, preServiceState)
			if data.Output.Err != "" {
				require.Error(t, err)
				require.EqualError(t, err, strings.ReplaceAll(data.Output.Err, "_", " "))
				return
			}
			newServiceState, err := statetransition.CalculateNewServiceStateWithPreimages(preimages, preServiceState, newTimeSlot)
			if data.Output.Err != "" {
				require.Error(t, err)
				require.EqualError(t, err, strings.ReplaceAll(data.Output.Err, "_", " "))
				return
			}
			require.NoError(t, err)
			newServiceStats, err := statetransition.CalculateNewServiceStatistics(block.Block{
				Extrinsic: block.Extrinsic{
					EP: preimages,
				},
			}, statetransition.AccumulationStats{})
			require.NoError(t, err)
			expectedPostServiceState := mapServiceState(t, data.PostState)

			require.Equal(t, expectedPostServiceState, newServiceState, "State after transition does not match expected state")
			expectedPostServiceStats := data.PostState.ServiceStatistics.To()
			require.Equal(t, expectedPostServiceStats, newServiceStats, "Service statistics after transition do not match expected statistics")
		})
	}
}

// mapPreState converts the pre-state from the test vector to internal service state
func mapServiceState(t *testing.T, state PreimageState) service.ServiceState {
	serviceState := make(service.ServiceState)

	for _, account := range state.Accounts {
		serviceId := block.ServiceId(account.ID)
		serviceAccount := service.ServiceAccount{
			PreimageLookup:         make(map[crypto.Hash][]byte),
			Balance:                1000, // Default values for fields not in test vector
			GasLimitForAccumulator: 100,
			GasLimitOnTransfer:     50,
		}

		// Map existing preimages
		for _, preimage := range account.Data.Preimages {
			hash := crypto.Hash(mustStringToHex(preimage.Hash))
			blob := mustStringToHex(preimage.Blob)
			serviceAccount.PreimageLookup[hash] = blob
		}

		// Map preimage metadata
		for _, meta := range account.Data.LookupMeta {
			hash := crypto.Hash(mustStringToHex(meta.Key.Hash))
			length := service.PreimageLength(meta.Key.Length)

			// Convert timeslot array
			var timeslots service.PreimageHistoricalTimeslots
			for _, slot := range meta.Value {
				timeslots = append(timeslots, jamtime.Timeslot(slot))
			}

			key, err := statekey.NewPreimageMeta(serviceId, hash, uint32(length))
			require.NoError(t, err)

			serviceAccount.InsertPreimageMeta(key, uint64(length), timeslots)
		}

		serviceState[serviceId] = serviceAccount
	}

	return serviceState
}

// mapPreimages converts preimage items from the test vector to internal preimage type
func mapPreimages(t *testing.T, items []PreimageItem) []block.Preimage {
	preimages := make([]block.Preimage, len(items))
	for i, item := range items {
		blobBytes, err := crypto.StringToHex(item.Blob)
		require.NoError(t, err, "Failed to parse blob hex")

		preimages[i] = block.Preimage{
			ServiceIndex: item.Requester,
			Data:         blobBytes,
		}
	}
	return preimages
}
