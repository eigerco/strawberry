//go:build integration

package integration

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/eigerco/strawberry/internal/block"
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/statetransition"
	"github.com/eigerco/strawberry/internal/testutils"
	jsonutils "github.com/eigerco/strawberry/internal/testutils/json"

	"github.com/stretchr/testify/require"
)

func ReadRecentHistoryJSONFile(filename string) (*RecentHistoryTestVector, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %v", err)
	}
	defer file.Close()

	bytes, err := io.ReadAll(file)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %v", err)
	}

	var data RecentHistoryTestVector
	if err := json.Unmarshal(bytes, &data); err != nil {
		return nil, fmt.Errorf("failed to unmarshal JSON: %v", err)
	}

	return &data, nil
}

// Empty history queue.
// "vectors/recenthistory/progress_blocks_history-1.json",
// Not empty nor full history queue.
// "vectors/recenthistory/progress_blocks_history-2.json",
// Fill the history queue.
// "vectors/recenthistory/progress_blocks_history-3.json",
// Shift the history queue.
// "vectors/recenthistory/progress_blocks_history-4.json",
func TestRecentHistory(t *testing.T) {
	files, err := os.ReadDir(fmt.Sprintf("vectors/recenthistory/%s", vectorsType))
	require.NoError(t, err, "failed to read directory: vectors/recenthistory/%s", vectorsType)

	for _, file := range files {
		if !strings.HasSuffix(file.Name(), ".json") {
			continue
		}
		t.Run(file.Name(), func(t *testing.T) {
			filePath := fmt.Sprintf("vectors/recenthistory/%s/%s", vectorsType, file.Name())
			tv, err := ReadRecentHistoryJSONFile(filePath)
			require.NoError(t, err, "failed to read JSON file: %s", filePath)

			// Inputs.
			headerHash := crypto.Hash(testutils.MustFromHex(t, tv.Input.HeaderHash))
			parentStateRoot := crypto.Hash(testutils.MustFromHex(t, tv.Input.ParentStateRoot))
			accumulateRoot := crypto.Hash(testutils.MustFromHex(t, tv.Input.AccumulateRoot))

			preRecentHistory := tv.PreState.Beta.To()

			workPackages := map[crypto.Hash]crypto.Hash{}
			for _, wp := range tv.Input.WorkPackages {
				hash := crypto.Hash(testutils.MustFromHex(t, wp.Hash))
				exportsRoot := crypto.Hash(testutils.MustFromHex(t, wp.ExportsRoot))

				workPackages[hash] = exportsRoot
			}

			intermediateRecentHistory := statetransition.CalculateIntermediateRecentHistory(block.Header{
				PriorStateRoot: parentStateRoot,
			}, preRecentHistory)
			newRecentHistory, err := statetransition.UpdateRecentHistory(headerHash, accumulateRoot, workPackages, intermediateRecentHistory)
			require.NoError(t, err)

			postRecentHistory := tv.PostState.Beta.To()
			require.Equal(t, postRecentHistory, newRecentHistory)
		})

	}
}

type RecentHistoryTestVector struct {
	Input struct {
		HeaderHash      string `json:"header_hash"`
		ParentStateRoot string `json:"parent_state_root"`
		AccumulateRoot  string `json:"accumulate_root"`
		WorkPackages    []struct {
			Hash        string `json:"hash"`
			ExportsRoot string `json:"exports_root"`
		} `json:"work_packages"`
	} `json:"input"`
	PreState  RecentHistoryTestState `json:"pre_state"`
	Output    interface{}            `json:"output"`
	PostState RecentHistoryTestState `json:"post_state"`
}

type RecentHistoryTestState struct {
	Beta jsonutils.RecentHistory `json:"beta"`
}
