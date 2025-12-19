//go:build tiny && traces

package integration

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/eigerco/strawberry/internal/state/serialization"
	"github.com/eigerco/strawberry/internal/state/serialization/statekey"
	"github.com/eigerco/strawberry/internal/statetransition"
	"github.com/eigerco/strawberry/internal/store"
	"github.com/eigerco/strawberry/pkg/db/pebble"
	"github.com/eigerco/strawberry/pkg/serialization/codec/jam"
)

func BenchmarkTracePreimagesLight(b *testing.B) {
	runTracesBenchmark(b, "traces/preimages_light")
}

func BenchmarkTracePreimages(b *testing.B) {
	runTracesBenchmark(b, "traces/preimages")
}

func BenchmarkTraceStorageLight(b *testing.B) {
	runTracesBenchmark(b, "traces/storage_light")
}

func BenchmarkTraceStorage(b *testing.B) {
	runTracesBenchmark(b, "traces/storage")
}

func BenchmarkTraceFallback(b *testing.B) {
	runTracesBenchmark(b, "traces/fallback")
}

func BenchmarkTraceSafrole(b *testing.B) {
	runTracesBenchmark(b, "traces/safrole")
}

func BenchmarkTraceFuzzy(b *testing.B) {
	runTracesBenchmark(b, "traces/fuzzy")
}

func BenchmarkTraceFuzzyLight(b *testing.B) {
	runTracesBenchmark(b, "traces/fuzzy_light")
}

func runTraceBenchmark(b *testing.B, filename string) {
	data, err := os.ReadFile(filename)
	if err != nil {
		b.Fatalf("failed to read trace file %q: %v", filename, err)
	}

	for i := 0; i < b.N; i++ {
		b.StopTimer()
		db, err := pebble.NewKVStore()
		if err != nil {
			b.Fatalf("failed to create pebble KV store: %v", err)
		}

		trieDB := store.NewTrie(db)
		chainDB := store.NewChain(db)

		var trace Trace
		err = jam.Unmarshal(data, &trace)
		if err != nil {
			b.Fatalf("failed to unmarshal trace from %q: %v", filename, err)
		}

		serializedState := map[statekey.StateKey][]byte{}
		for _, entry := range trace.PreState.KeyValues {
			serializedState[entry.Key] = entry.Value
		}

		currentState, err := serialization.DeserializeState(serializedState)
		if err != nil {
			b.Fatalf("failed to deserialize state: %v", err)
		}

		b.StartTimer()

		block := trace.Block
		err = statetransition.UpdateState(
			&currentState,
			block,
			chainDB,
			trieDB,
		)
		if err != nil {
			b.Fatalf("failed to update state for block: %v", err)
		}

		b.StopTimer()
		err = db.Close()
		if err != nil {
			b.Fatalf("failed to close database: %v", err)
		}
	}
}

func runTracesBenchmark(b *testing.B, directory string) {
	files, err := filepath.Glob(fmt.Sprintf("%s/*.bin", directory))
	if err != nil {
		b.Fatalf("failed to glob trace files in %q: %v", directory, err)
	}

	if len(files) == 0 {
		b.Fatalf("no trace files found in %q", directory)
	}

	sort.Strings(files)

	for _, file := range files {
		if filepath.Base(file) == "genesis.bin" {
			continue // Skip the genesis trace since this is mostly there for reference.
		}
		b.Run(filepath.Base(file), func(b *testing.B) {
			runTraceBenchmark(b, file)
		})
	}
}
