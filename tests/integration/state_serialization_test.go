//go:build integration

package integration

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/eigerco/strawberry/internal/state/serialization"
	"github.com/eigerco/strawberry/internal/state/serialization/statekey"
	"github.com/eigerco/strawberry/internal/testutils"
)

func TestStateSerialization(t *testing.T) {
	b, err := os.ReadFile("vectors/state_serialization/trace.json")
	require.NoError(t, err)

	tv := TraceVector{}
	err = json.Unmarshal(b, &tv)
	require.NoError(t, err)

	serializedState := map[statekey.StateKey][]byte{}
	for _, kv := range tv.PostState.KeyVals {
		key := testutils.MustFromHex(t, kv.Key)
		value := testutils.MustFromHex(t, kv.Value)
		serializedState[statekey.StateKey(key)] = value
	}

	decodedState, err := serialization.DeserializeState(serializedState)
	require.NoError(t, err)

	newSerializedState, err := serialization.SerializeState(decodedState)
	require.NoError(t, err)

	for key, originalValue := range serializedState {
		value, ok := newSerializedState[key]
		require.True(t, ok, "missed key %s", hex.EncodeToString(key[:]))

		require.Equal(t, hex.EncodeToString(originalValue), hex.EncodeToString(value),
			"key %s", hex.EncodeToString(key[:]))
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
