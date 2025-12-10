//go:build tiny && integration

package integration

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	jsonutils "github.com/eigerco/strawberry/internal/testutils/json"
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

func TestJSONBlockShapshotRestoreDump(t *testing.T) {
	jsonDumpBytes, err := os.ReadFile("vectors_community/json/block.json")
	if err != nil {
		t.Fatalf("Error opening file: %v", err)
	}

	restoredBlock := jsonutils.RestoreBlockSnapshot(jsonDumpBytes)

	newDump := jsonutils.DumpBlockSnapshot(restoredBlock)

	require.JSONEq(t, string(jsonDumpBytes), newDump)

}
