//go:build tiny && traces

package integration

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/eigerco/strawberry/pkg/log"
	"github.com/rs/zerolog"

	"github.com/eigerco/strawberry/internal/common"
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/pmezard/go-difflib/difflib"
	"github.com/stretchr/testify/require"

	"github.com/eigerco/strawberry/internal/state"
	"github.com/eigerco/strawberry/internal/state/merkle"
	"github.com/eigerco/strawberry/internal/state/serialization"
	"github.com/eigerco/strawberry/internal/state/serialization/statekey"
	"github.com/eigerco/strawberry/internal/statetransition"
	"github.com/eigerco/strawberry/internal/store"
	"github.com/eigerco/strawberry/internal/testutils"
	jsonutils "github.com/eigerco/strawberry/internal/testutils/json"
	"github.com/eigerco/strawberry/pkg/db/pebble"
)

func init() {
	log.Init(log.Options{LogLevel: zerolog.InfoLevel})
}

func TestTracePreimagesLight(t *testing.T) {
	runTracesTests(t, "traces/preimages_light")
}

func TestTracePreimages(t *testing.T) {
	runTracesTests(t, "traces/preimages")
}

func TestTraceStorageLight(t *testing.T) {
	runTracesTests(t, "traces/storage_light")
}

func TestTraceStorage(t *testing.T) {
	runTracesTests(t, "traces/storage")
}

func TestTraceFallback(t *testing.T) {
	runTracesTests(t, "traces/fallback")
}

func TestTraceSafrole(t *testing.T) {
	runTracesTests(t, "traces/safrole")
}

func runTracesTests(t *testing.T, directory string) {
	files, err := filepath.Glob(fmt.Sprintf("%s/*.json", directory))
	require.NoError(t, err)
	require.NotEmpty(t, files, "no JSON files found in traces/fallback/")

	sort.Strings(files)

	for _, file := range files {
		if filepath.Base(file) == "genesis.json" {
			continue // Skip the genesis trace since this is mostly there for reference.
		}
		t.Run(filepath.Base(file), func(t *testing.T) {
			t.Parallel()
			runTraceTest(t, file)
		})
	}
}

func runTraceTest(t *testing.T, filename string) {
	log.Root.Info().Msg(fmt.Sprintf("NumberOfValidators: %d", common.NumberOfValidators))
	data, err := os.ReadFile(filename)
	require.NoError(t, err)

	db, err := pebble.NewKVStore()
	require.NoError(t, err)
	defer func() {
		err := db.Close()
		require.NoError(t, err, "failed to close db")
	}()

	trieDB := store.NewTrie(db)
	require.NoError(t, err)
	chainDB := store.NewChain(db)
	require.NoError(t, err)

	var trace TraceJSON
	err = json.Unmarshal(data, &trace)
	require.NoError(t, err)

	_, currentState := parseTrace(t, trace.PreState, trieDB)
	postStateRoot, postState := parseTrace(t, trace.PostState, trieDB)
	block := trace.Block.To()

	err = statetransition.UpdateState(
		currentState,
		block,
		chainDB,
		trieDB,
	)
	require.NoError(t, err)

	RequireEqualStates(t, postState, currentState)

	// Double check the state root matches the one in the trace.
	currentStateRoot, err := merkle.MerklizeState(*currentState, trieDB)
	require.NoError(t, err, "failed to merklize current state")
	require.Equal(t, postStateRoot, currentStateRoot, "state root mismatch")

}

// RequireEqualStates compares two state.State structs and fails the test if
// they are not equal. Similar to testify's require.Equal, but provides a more
// useful diff output.
func RequireEqualStates(t *testing.T, expected, actual *state.State) {
	expectedDump := jsonutils.DumpStateSnapshot(*expected)
	actualDump := jsonutils.DumpStateSnapshot(*actual)

	diff, _ := difflib.GetUnifiedDiffString(difflib.UnifiedDiff{
		A:        difflib.SplitLines(expectedDump),
		B:        difflib.SplitLines(actualDump),
		FromFile: "Expected",
		FromDate: "",
		ToFile:   "Actual",
		ToDate:   "",
		Context:  1,
	})
	if diff != "" {
		t.Fatalf("State mismatch:\n%s", diff)
	}
}

type TraceJSON struct {
	PreState  TraceJSONState  `json:"pre_state"`
	PostState TraceJSONState  `json:"post_state"`
	Block     jsonutils.Block `json:"block"`
}

type TraceJSONStateEntry struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

type TraceJSONState struct {
	StateRoot string                `json:"state_root"`
	Keyvals   []TraceJSONStateEntry `json:"keyvals"`
}

// parseTrace deserializes a TraceState into a state.State and validates that
// the state root matches the one provided by the trace. Returns the state root
// and deserialized state.
func parseTrace(t *testing.T, traceState TraceJSONState, trie *store.Trie) (crypto.Hash, *state.State) {
	serializedState := map[statekey.StateKey][]byte{}
	for _, entry := range traceState.Keyvals {
		stateKeyBytes := testutils.MustFromHex(t, entry.Key)
		stateKey := statekey.StateKey{}
		copy(stateKey[:], stateKeyBytes)

		valueBytes := testutils.MustFromHex(t, entry.Value)

		serializedState[stateKey] = valueBytes
	}

	state, err := serialization.DeserializeState(serializedState)
	require.NoError(t, err, "failed to deserialize state")

	stateRoot := crypto.Hash{}
	stateRootBytes := testutils.MustFromHex(t, traceState.StateRoot)
	copy(stateRoot[:], stateRootBytes)

	expectedStateRoot, err := merkle.MerklizeState(state, trie)
	require.NoError(t, err, "failed to merklize state")

	require.Equal(t, expectedStateRoot, stateRoot, "state root mismatch")

	return stateRoot, &state
}
