//go:build conformance && traces

package integration

import (
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestTraceFuzzer(t *testing.T) {
	entries, err := os.ReadDir("traces/fuzzer")
	require.NoError(t, err)

	var directories []string
	for _, entry := range entries {
		if entry.IsDir() {
			directories = append(directories, entry.Name())
		}
	}
	require.NotEmpty(t, directories, "no fuzzer directories found in traces/fuzzer")

	sort.Strings(directories)
	for _, directory := range directories {
		t.Run(directory, func(t *testing.T) {
			t.Parallel()
			runTracesTests(t, filepath.Join("traces/fuzzer", directory))
		})
	}
}
