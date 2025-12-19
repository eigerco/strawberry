//go:build tiny && traces

package integration

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/eigerco/strawberry/internal/block"
	"github.com/eigerco/strawberry/pkg/conformance"
	"github.com/eigerco/strawberry/pkg/network/handlers"
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

func runTraceBenchmark(b *testing.B, conn net.Conn, filename string) {
	data, err := os.ReadFile(filename)
	if err != nil {
		b.Fatalf("failed to read trace file %q: %v", filename, err)
	}
	var trace Trace
	err = jam.Unmarshal(data, &trace)
	if err != nil {
		b.Fatalf("failed to unmarshal trace from %q: %v", filename, err)
	}

	ctx := context.Background()
	// Serialize Initialize message
	initMsgBytes, err := jam.Marshal(conformance.NewMessage(conformance.Initialize{
		Header: block.Header{},
		State: conformance.State{
			StateItems: trace.PreState.KeyValues,
		},
		Ancestry: conformance.Ancestry{
			Items: []conformance.AncestryItem{},
		},
	}))
	require.NoError(b, err)

	// Serialize ImportBlock message
	blockImportMsgBytes, err := jam.Marshal(conformance.NewMessage(conformance.ImportBlock{
		Block: trace.Block,
	}))
	require.NoError(b, err)
	for i := 0; i < b.N; i++ {
		// Create the Initialize message (Prestate)

		// Send the Initialize message
		err = handlers.WriteMessageWithContext(ctx, conn, initMsgBytes)
		require.NoError(b, err)
		// Read the response to the Initialize message
		initResponse, err := handlers.ReadMessageWithContext(ctx, conn)
		require.NoError(b, err)
		require.NotEmpty(b, initResponse)

		// Only time the import block logic
		b.StartTimer()
		// Send the ImportBlock message
		err = handlers.WriteMessageWithContext(ctx, conn, blockImportMsgBytes)
		require.NoError(b, err)
		// Read the response to the ImportBlock message (StateRoot)
		importResponse, err := handlers.ReadMessageWithContext(ctx, conn)
		require.NoError(b, err)
		require.NotEmpty(b, importResponse)
		b.StopTimer()
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

	// Create a connection and first message (PeerInfo)
	conn, err := net.Dial("unix", "/tmp/jam_target.sock")
	require.NoError(b, err)
	defer func() {
		require.NoError(b, conn.Close())
	}()
	msgBytes, err := jam.Marshal(peerInfo)
	require.NoError(b, err)
	// Send PeerInfo message
	ctx := context.Background()
	err = handlers.WriteMessageWithContext(ctx, conn, msgBytes)
	require.NoError(b, err)
	// Read the response
	response, err := handlers.ReadMessageWithContext(ctx, conn)
	require.NoError(b, err)
	require.NotEmpty(b, response)
	respMsg := &conformance.Message{}
	err = jam.Unmarshal(response.Content, respMsg)
	require.NoError(b, err)
	require.NotNil(b, respMsg)

	data, err := os.ReadFile(filepath.Join(directory, "genesis.bin"))
	if err != nil {
		b.Fatalf("failed to genesis.bin: %v", err)
	}
	var genesis Genesis
	err = jam.Unmarshal(data, &genesis)
	if err != nil {
		b.Fatalf("failed to genesis.bin: %v", err)
	}
	require.NoError(b, err)
	require.NotEmpty(b, genesis)

	// Create the Initialize message (Prestate)
	initMessage := conformance.Initialize{
		Header: genesis.Header,
		State: conformance.State{
			StateItems: genesis.State.KeyValues,
		},
		Ancestry: conformance.Ancestry{Items: []conformance.AncestryItem{}},
	}
	initMsg := conformance.NewMessage(initMessage)
	initMsgBytes, err := jam.Marshal(initMsg)

	// Send the Initialize genesis message
	err = handlers.WriteMessageWithContext(ctx, conn, initMsgBytes)
	require.NoError(b, err)
	// Read the response to the Initialize genesis message
	initResponse, err := handlers.ReadMessageWithContext(ctx, conn)
	require.NoError(b, err)
	require.NotEmpty(b, initResponse)
	require.NoError(b, err)

	for _, file := range files {
		if filepath.Base(file) == "genesis.bin" {
			continue // Skip the genesis trace since this is mostly there for reference.
		}
		b.Run(filepath.Base(file), func(b *testing.B) {
			runTraceBenchmark(b, conn, file)
		})
	}
}

var peerInfo = conformance.NewMessage(conformance.PeerInfo{
	FuzzVersion:  1,
	FuzzFeatures: conformance.FeatureFork,
	JamVersion: conformance.Version{
		Major: 0,
		Minor: 7,
		Patch: 2,
	},
	AppVersion: conformance.Version{
		Major: 1,
		Minor: 0,
		Patch: 0,
	},
	Name: []byte("test-node"),
})
