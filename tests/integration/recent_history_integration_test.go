//go:build integration

package integration_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/eigerco/strawberry/internal/block"
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/statetransition"
	"github.com/eigerco/strawberry/internal/testutils"
	jsonutils "github.com/eigerco/strawberry/internal/testutils/json"

	"github.com/stretchr/testify/require"
)

func TestRecentHistory(t *testing.T) {
	testFiles := []string{
		// Empty history queue.
		"vectors/recenthistory/progress_blocks_history-1.json",

		// Not empty nor full history queue.
		"vectors/recenthistory/progress_blocks_history-2.json",

		// Fill the history queue.
		"vectors/recenthistory/progress_blocks_history-3.json",

		// Shift the history queue.
		"vectors/recenthistory/progress_blocks_history-4.json",
	}

	for _, tf := range testFiles {
		t.Run(filepath.Base(tf), func(t *testing.T) {
			file, err := os.ReadFile(tf)
			require.NoError(t, err)

			var tv RecentHistoryTestVector
			err = json.Unmarshal(file, &tv)
			require.NoError(t, err)

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
