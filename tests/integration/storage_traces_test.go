//go:build integration

package integration

import (
	"path/filepath"
	"sort"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestTracePreimagesLight(t *testing.T) {
	files, err := filepath.Glob("traces/preimages_light/*.json")
	require.NoError(t, err)
	require.NotEmpty(t, files, "no JSON files found in traces/preimages_light/")

	sort.Strings(files)

	for _, file := range files {
		if filepath.Base(file) == "genesis.json" {
			continue // Skip the genesis trace since this is mostly there for reference.
		}
		t.Run(filepath.Base(file), func(t *testing.T) {
			runTraceFallbackTest(t, file)
		})
	}
}

func TestTracePreimages(t *testing.T) {
	files, err := filepath.Glob("traces/preimages/*.json")
	require.NoError(t, err)
	require.NotEmpty(t, files, "no JSON files found in traces/preimages/")

	sort.Strings(files)

	for _, file := range files {
		if filepath.Base(file) == "genesis.json" {
			continue // Skip the genesis trace since this is mostly there for reference.
		}
		t.Run(filepath.Base(file), func(t *testing.T) {
			runTraceFallbackTest(t, file)
		})
	}
}

func TestTraceStorageLight(t *testing.T) {
	files, err := filepath.Glob("traces/storage_light/*.json")
	require.NoError(t, err)
	require.NotEmpty(t, files, "no JSON files found in traces/storage_light/")

	sort.Strings(files)

	for _, file := range files {
		if filepath.Base(file) == "genesis.json" {
			continue // Skip the genesis trace since this is mostly there for reference.
		}
		t.Run(filepath.Base(file), func(t *testing.T) {
			runTraceFallbackTest(t, file)
		})
	}
}

func TestTraceStorage(t *testing.T) {
	files, err := filepath.Glob("traces/storage/*.json")
	require.NoError(t, err)
	require.NotEmpty(t, files, "no JSON files found in traces/storage/")

	sort.Strings(files)

	for _, file := range files {
		if filepath.Base(file) == "genesis.json" {
			continue // Skip the genesis trace since this is mostly there for reference.
		}
		t.Run(filepath.Base(file), func(t *testing.T) {
			runTraceFallbackTest(t, file)
		})
	}
}
