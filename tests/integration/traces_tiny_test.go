//go:build tiny && traces

package integration

import (
	"testing"
)

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

func TestTraceFuzzy(t *testing.T) {
	runTracesTests(t, "traces/fuzzy")
}

func TestTraceFuzzyLight(t *testing.T) {
	runTracesTests(t, "traces/fuzzy_light")
}
