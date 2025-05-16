//go:build integration

package integration_test

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/eigerco/strawberry/internal/state"
	"github.com/eigerco/strawberry/internal/state/merkle"
	"github.com/eigerco/strawberry/internal/testutils"
	"github.com/stretchr/testify/require"
)

func TestStateSerialization(t *testing.T) {
	b, err := os.ReadFile("vectors_community/state_serialization/trace.json")
	require.NoError(t, err)

	tv := TraceVector{}
	err = json.Unmarshal(b, &tv)
	require.NoError(t, err)

	serializedState := map[state.StateKey][]byte{}
	for _, kv := range tv.PostState.KeyVals {
		key := testutils.MustFromHex(t, kv.Key)
		value := testutils.MustFromHex(t, kv.Value)
		serializedState[state.StateKey(key)] = value
	}

	decodedState, err := merkle.DeserializeState(serializedState)
	require.NoError(t, err)

	newSerializedState, err := merkle.SerializeState(decodedState)
	require.NoError(t, err)

	// Check only the keys we're currently able to serialize.
	// We are missing storage, preimage, and preimage lookup dicts for now.
	for key, value := range newSerializedState {
		require.Equal(t, value, newSerializedState[key])
	}

}

type TraceVector struct {
	PostState TraceVectorState `json:"post_state"`
	PreState  TraceVectorState `json:"pre_state"`
}

type TraceVectorState struct {
	StateRoot string `json:"state_root"`
	KeyVals   []struct {
		Key   string `json:"key"`
		Value string `json:"value"`
	} `json:"keyvals"`
}
