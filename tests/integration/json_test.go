//go:build integration

package integration_test

import (
	"os"
	"testing"

	jsonutils "github.com/eigerco/strawberry/internal/testutils/json"
	"github.com/stretchr/testify/require"
)

// Tests that we can decode a JSON state dump and re-encode it.
// Dump taken from: https://github.com/jam-duna/jamtestnet
func TestJSONStateShapshotRestoreDump(t *testing.T) {
	jsonDumpBytes, err := os.ReadFile("vectors_community/json/statedump.json")
	if err != nil {
		t.Fatalf("Error opening file: %v", err)
	}

	state := jsonutils.RestoreStateSnapshot(jsonDumpBytes)

	newDump := jsonutils.DumpStateSnapshot(state)

	require.JSONEq(t, string(jsonDumpBytes), newDump)

}
