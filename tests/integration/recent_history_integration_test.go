//go:build integration

package integration_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/eigerco/strawberry/internal/block"
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/merkle/mountain_ranges"
	"github.com/eigerco/strawberry/internal/state"
	"github.com/eigerco/strawberry/internal/statetransition"
	"github.com/eigerco/strawberry/internal/testutils"
	"github.com/stretchr/testify/require"
)

func TestRecentHistory(t *testing.T) {
	testFiles := []string{
		// Empty hjstory queue.
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

			preRecentHistory := toRecentHistory(t, tv.PreState)

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

			postRecentHistory := toRecentHistory(t, tv.PostState)
			require.Equal(t, postRecentHistory, newRecentHistory)
		})

	}
}

// TODO this is a temporary mapping for recent history, when we have new test
// vectors for v0.6.7 this will need to be updated.
func toRecentHistory(t *testing.T, s RecentHistoryTestVectorState) state.RecentHistory {
	newBlocks := make([]state.BlockState, len(s.Beta))
	for i, bs := range s.Beta {
		accResultMMR := make([]*crypto.Hash, len(bs.MMR.Peaks))
		for i, p := range bs.MMR.Peaks {
			if p != nil {
				peak := crypto.Hash(testutils.MustFromHex(t, *p))
				accResultMMR[i] = &peak
			}
		}
		mountainRange := mountain_ranges.New()
		beefRoot := mountainRange.SuperPeak(accResultMMR, crypto.KeccakData)

		workReportHashes := map[crypto.Hash]crypto.Hash{}
		for _, wr := range bs.Reported {
			hash := crypto.Hash(testutils.MustFromHex(t, wr.Hash))
			exportsRoot := crypto.Hash(testutils.MustFromHex(t, wr.ExportsRoot))

			workReportHashes[hash] = exportsRoot
		}

		newBlocks[i] = state.BlockState{
			HeaderHash: crypto.Hash(testutils.MustFromHex(t, bs.HeaderHash)),
			StateRoot:  crypto.Hash(testutils.MustFromHex(t, bs.StateRoot)),
			BeefyRoot:  beefRoot,
			Reported:   workReportHashes,
		}
	}

	var outputLog []*crypto.Hash
	if len(s.Beta) > 0 {
		lastBlock := s.Beta[len(s.Beta)-1]
		for _, p := range lastBlock.MMR.Peaks {
			if p == nil {
				outputLog = append(outputLog, nil)
				continue
			}
			peak := crypto.Hash(testutils.MustFromHex(t, *p))
			outputLog = append(outputLog, &peak)
		}

	}

	return state.RecentHistory{
		BlockHistory:          newBlocks,
		AccumulationOutputLog: outputLog,
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
	PreState  RecentHistoryTestVectorState `json:"pre_state"`
	Output    interface{}                  `json:"output"`
	PostState RecentHistoryTestVectorState `json:"post_state"`
}

type RecentHistoryTestVectorState struct {
	Beta []struct {
		HeaderHash string `json:"header_hash"`
		MMR        struct {
			Peaks []*string `json:"peaks"`
		} `json:"mmr"`
		StateRoot string `json:"state_root"`
		Reported  []struct {
			Hash        string `json:"hash"`
			ExportsRoot string `json:"exports_root"`
		} `json:"reported"`
	} `json:"beta"`
}
