//go:build integration

package integration

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/eigerco/strawberry/internal/block"
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/pkg/serialization/codec/jam"
)

type KeyValue struct {
	Key   [31]byte `json:"key"`
	Value []byte   `json:"value"`
}

type RawState struct {
	StateRoot crypto.Hash
	KeyValues []KeyValue
}

type Trace struct {
	PreState  RawState
	Block     block.Block
	PostState RawState
}

func TestExtrinsicHash(t *testing.T) {
	// Traces taken from: https://github.com/davxy/jam-test-vectors/blob/traces/traces
	files, err := filepath.Glob("vectors/extrinsic_hash/*.bin")
	require.NoError(t, err)
	require.NotEmpty(t, files, "No test vectors found.")

	for _, file := range files {
		filename := strings.TrimSuffix(filepath.Base(file), filepath.Ext(file))
		t.Run(filename, func(t *testing.T) {
			jsonFilename := strings.TrimSuffix(file, filepath.Ext(file)) + ".json"
			_, err := os.Stat(jsonFilename)
			require.NoError(t, err, "Missing matching JSON file for test vector.")

			b, err := os.ReadFile(file)
			require.NoError(t, err)

			var trace Trace
			err = jam.Unmarshal(b, &trace)
			require.NoError(t, err)

			hash, err := trace.Block.Extrinsic.Hash()
			require.NoError(t, err)

			require.Equal(t, hex.EncodeToString(trace.Block.Header.ExtrinsicHash[:]), hex.EncodeToString(hash[:]))
		})
	}
}
