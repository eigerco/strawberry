//go:build integration

package integration

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/eigerco/strawberry/internal/block"
	"github.com/eigerco/strawberry/pkg/serialization/codec/jam"
	"github.com/stretchr/testify/require"
)

func TestExtrinsicHash(t *testing.T) {
	// Blocks taken from: https://github.com/jam-duna/jamtestnet/tree/main/data/orderedaccumulation/blocks
	files, err := filepath.Glob("vectors_community/extrinsic_hash/*.bin")
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

			var block block.Block
			err = jam.Unmarshal(b, &block)
			require.NoError(t, err)

			hash, err := block.Extrinsic.Hash()
			require.NoError(t, err)

			require.Equal(t, hex.EncodeToString(block.Header.ExtrinsicHash[:]), hex.EncodeToString(hash[:]))
		})
	}
}
