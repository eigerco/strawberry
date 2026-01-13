//go:build conformance

package conformance

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/eigerco/strawberry/pkg/network/handlers"
	"github.com/eigerco/strawberry/pkg/serialization/codec/jam"
	"github.com/stretchr/testify/require"
)

type PeerInfoChoice struct {
	Choice uint8
	PeerInfo
}

type ErrorChoice struct {
	Choice uint8
	Error
}

type InitializeChoice struct {
	Choice uint8
	Initialize
}

type StateRootChoice struct {
	Choice uint8
	StateRoot
}

type ImportBlockChoice struct {
	Choice uint8
	ImportBlock
}

type GetStateChoice struct {
	Choice uint8
	GetState
}

type FuzzerType interface {
	isFuzzerType()
}

func (PeerInfoChoice) isFuzzerType()    {}
func (ErrorChoice) isFuzzerType()       {}
func (InitializeChoice) isFuzzerType()  {}
func (StateRootChoice) isFuzzerType()   {}
func (ImportBlockChoice) isFuzzerType() {}
func (GetStateChoice) isFuzzerType()    {}

var tracesDir = "traces/forks"

func getFuzzerFileNames(t *testing.T) []string {
	files, err := filepath.Glob(tracesDir + "/*fuzzer*.bin")
	require.NoError(t, err)
	require.Greater(t, len(files), 0, "no fuzzer files found in folder "+tracesDir)
	return files
}

func getTargetFileNames(t *testing.T) []string {
	files, err := filepath.Glob(tracesDir + "/*target*.bin")
	require.NoError(t, err)
	require.Greater(t, len(files), 0, "no target files found in folder "+tracesDir)
	return files
}

func getFuzzerFilesFromExamplesDir(t *testing.T) ([]FuzzerType, error) {
	files := getFuzzerFileNames(t)

	var fuzzerFiles []FuzzerType
	for _, file := range files {
		b, err := os.ReadFile(file)
		require.NoError(t, err)

		var fuzzer FuzzerType
		baseName := filepath.Base(file)

		switch {
		case strings.Contains(baseName, "peer_info"):
			var peerInfo PeerInfoChoice
			err := jam.Unmarshal(b, &peerInfo)
			require.NoError(t, err)
			fuzzer = peerInfo
		case strings.Contains(baseName, "initialize"):
			var initialize InitializeChoice
			err := jam.Unmarshal(b, &initialize)
			require.NoError(t, err)
			fuzzer = initialize
		case strings.Contains(baseName, "import_block"):
			var importBlock ImportBlockChoice
			err := jam.Unmarshal(b, &importBlock)
			require.NoError(t, err)
			fuzzer = importBlock
		case strings.Contains(baseName, "get_state"):
			var getState GetStateChoice
			err := jam.Unmarshal(b, &getState)
			require.NoError(t, err)
			fuzzer = getState
		default:
			continue
		}
		fuzzerFiles = append(fuzzerFiles, fuzzer)
	}
	return fuzzerFiles, nil
}

func getTargetsFromExamplesDir(t *testing.T) ([]any, error) {
	files := getTargetFileNames(t)

	var targets []any
	for _, file := range files {
		b, err := os.ReadFile(file)
		require.NoError(t, err)
		var msg Message
		err = jam.Unmarshal(b, &msg)
		require.NoError(t, err)
		targets = append(targets, msg.Get())
	}
	return targets, nil
}

func createTargetNode(t *testing.T) (*Node, func()) {
	socketPath := "jam_test_target.sock"
	os.Remove(socketPath)
	appName := []byte("polkajam")
	appVersion := Version{Major: 0, Minor: 1, Patch: 25}
	jamVersion := Version{Major: 0, Minor: 7, Patch: 0}
	features := FeatureFork
	node := NewNode(socketPath, appName, appVersion, jamVersion, features)
	cleanup := func() {
		os.Remove(socketPath)
	}
	return node, cleanup
}

// TODO update conformance traces to v0.7.1 when they are released
func TestNoForksTraces(t *testing.T) {
	t.Skip("The conformance traces are not yet updated to v0.7.1")
	requests, err := getFuzzerFilesFromExamplesDir(t)
	require.NoError(t, err)
	responses, err := getTargetsFromExamplesDir(t)
	require.NoError(t, err)
	require.Equal(t, len(requests), len(responses), "number of fuzzer files and target files should be equal")
	node, cleanup := createTargetNode(t)
	t.Cleanup(cleanup)
	serverErrChan := make(chan error, 1)
	go func() {
		serverErrChan <- node.Start()
	}()
	defer node.Stop()
	select {
	case err := <-serverErrChan:
		t.Fatalf("Server failed to start: %v", err)
	case <-time.After(100 * time.Millisecond):
		t.Log("Server started successfully.")
	}

	for i, req := range requests {
		if t.Failed() {
			break
		}
		t.Run(fmt.Sprintf("Fuzzer_file_%d", i), func(t *testing.T) {
			expected := responses[i]
			conn, err := net.Dial("unix", "jam_test_target.sock")
			require.NoError(t, err)
			defer conn.Close()

			msgBytes, err := jam.Marshal(req)
			require.NoError(t, err)

			ctx := context.Background()
			err = handlers.WriteMessageWithContext(ctx, conn, msgBytes)
			require.NoError(t, err)

			response, err := handlers.ReadMessageWithContext(ctx, conn)
			require.NoError(t, err)

			respMsg := &Message{}
			err = jam.Unmarshal(response.Content, respMsg)
			require.NoError(t, err)
			// If running the faulty folder traces/faulty
			// 29 is expected to return wrong state root in order to trigger the fuzzer to request `GetState`
			// 30 is supposed to return wrong state as we have different state compared expected due to 20
			// `In this scenario, the target responds with its current state, which is expected not to match a correctly computed state.`
			// if i != 29 && i != 30 {
			// 	require.Equal(t, respMsg.Get(), expected)
			// }
			require.Equal(t, respMsg.Get(), expected)
		})
	}
}
