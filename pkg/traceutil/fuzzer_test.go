package traceutil

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/eigerco/strawberry/internal/state/serialization"
	"github.com/eigerco/strawberry/pkg/conformance"
	"github.com/eigerco/strawberry/pkg/network/handlers"
	"github.com/eigerco/strawberry/pkg/serialization/codec/jam"
	"github.com/eigerco/strawberry/tests/integration"
	"github.com/stretchr/testify/require"
)

var vectorsDir = "vectors"

// read the file at the given path within the vectors directory
func readVectorFile(path string) ([]byte, error) {
	return os.ReadFile(filepath.Join(vectorsDir, path))
}

func ParseTraceFile(t *testing.T, path string) (integration.Trace, error) {
	var trace integration.Trace
	data, err := readVectorFile(path)
	require.NoError(t, err)
	err = jam.Unmarshal(data, &trace)
	require.NoError(t, err)
	return trace, nil
}

func ParseGenesisFile(t *testing.T, path string) (integration.Genesis, error) {
	var genesis integration.Genesis
	data, err := readVectorFile(path)
	require.NoError(t, err)
	err = jam.Unmarshal(data, &genesis)
	require.NoError(t, err)
	return genesis, nil
}

func TestVectorFileWithGenesis(t *testing.T) {
	// Parse the trace vector
	t.Skip("This is used for manual testing with a local jam target")
	genesis, err := ParseGenesisFile(t, "genesis.bin")
	require.NoError(t, err)
	require.NotEmpty(t, genesis)
	block, err := ParseTraceFile(t, "00000001.bin")
	require.NoError(t, err)
	require.NotEmpty(t, block)

	// Create a connection and first message (PeerInfo)
	peerInfoMessage := CreatePeerInfoMessage()
	conn, err := net.Dial("unix", "/tmp/jam_target.sock")
	require.NoError(t, err)
	defer func() {
		require.NoError(t, conn.Close())
	}()
	msgBytes, err := jam.Marshal(peerInfoMessage)
	require.NoError(t, err)
	// Send PeerInfo message
	ctx := context.Background()
	err = handlers.WriteMessageWithContext(ctx, conn, msgBytes)
	require.NoError(t, err)
	// Read the response
	response, err := handlers.ReadMessageWithContext(ctx, conn)
	require.NoError(t, err)
	require.NotEmpty(t, response)
	respMsg := &conformance.Message{}
	err = jam.Unmarshal(response.Content, respMsg)
	require.NoError(t, err)
	require.NotNil(t, respMsg)

	// Create the Initialize message (Prestate)
	initMessage := GenesisToConformanceInitialize(genesis)
	initMsg := conformance.NewMessage(initMessage)
	initMsgBytes, err := jam.Marshal(initMsg)
	require.NoError(t, err)
	// Send the Initialize message
	err = handlers.WriteMessageWithContext(ctx, conn, initMsgBytes)
	require.NoError(t, err)
	// Read the response to the Initialize message
	initResponse, err := handlers.ReadMessageWithContext(ctx, conn)
	require.NoError(t, err)
	require.NotEmpty(t, initResponse)
	initRespMsg := &conformance.Message{}
	err = jam.Unmarshal(initResponse.Content, initRespMsg)
	require.NoError(t, err)
	require.NotNil(t, initRespMsg)

	// Send the ImportBlock message
	blockImportMessage := TraceToConformanceImportBlock(block)
	blockImportMsg := conformance.NewMessage(blockImportMessage)
	blockImportMsgBytes, err := jam.Marshal(blockImportMsg)
	require.NoError(t, err)
	err = handlers.WriteMessageWithContext(ctx, conn, blockImportMsgBytes)
	require.NoError(t, err)
	// Read the response to the ImportBlock message (StateRoot)
	importResponse, err := handlers.ReadMessageWithContext(ctx, conn)
	require.NoError(t, err)
	require.NotEmpty(t, importResponse)
	importRespMsg := &conformance.Message{}
	err = jam.Unmarshal(importResponse.Content, importRespMsg)
	require.NoError(t, err)
	require.NotNil(t, importRespMsg)

	// Create the GetState message to request the state
	headerHash, err := block.Block.Header.Hash()
	require.NoError(t, err)
	getStateMessage := CreateGetStateMessage(headerHash)
	getStateMsgBytes, err := jam.Marshal(getStateMessage)
	require.NoError(t, err)
	err = handlers.WriteMessageWithContext(ctx, conn, getStateMsgBytes)
	require.NoError(t, err)
	// Read the response to the GetState message (State)
	getStateResponse, err := handlers.ReadMessageWithContext(ctx, conn)
	require.NoError(t, err)
	require.NotEmpty(t, getStateResponse)
	getStateRespMsg := &conformance.Message{}
	err = jam.Unmarshal(getStateResponse.Content, getStateRespMsg)
	require.NoError(t, err)
	require.NotNil(t, getStateRespMsg)
	require.NotEmpty(t, getStateRespMsg.Get().(conformance.State).StateItems)

	// Restore state from the response
	keyValues := getStateRespMsg.Get().(conformance.State)
	require.NotEmpty(t, keyValues.StateItems)
	stateMap := KeyValueStateToStateMap(keyValues.StateItems)
	_, err = serialization.DeserializeState(stateMap)
	require.NoError(t, err, "failed to deserialize state")
}

func TestVectorFileOnly(t *testing.T) {
	// Parse the trace vector
	t.Skip("This is used for manual testing with a local jam target")
	data, err := ParseTraceFile(t, "00000001.bin")
	require.NoError(t, err)
	require.NotEmpty(t, data)

	// Create a connection and first message (PeerInfo)
	peerInfoMessage := CreatePeerInfoMessage()
	conn, err := net.Dial("unix", "/tmp/jam_target.sock")
	require.NoError(t, err)
	defer func() {
		require.NoError(t, conn.Close())
	}()
	msgBytes, err := jam.Marshal(peerInfoMessage)
	require.NoError(t, err)
	// Send PeerInfo message
	ctx := context.Background()
	err = handlers.WriteMessageWithContext(ctx, conn, msgBytes)
	require.NoError(t, err)
	// Read the response
	response, err := handlers.ReadMessageWithContext(ctx, conn)
	require.NoError(t, err)
	require.NotEmpty(t, response)
	respMsg := &conformance.Message{}
	err = jam.Unmarshal(response.Content, respMsg)
	require.NoError(t, err)
	require.NotNil(t, respMsg)

	// Create the Initialize message (Prestate)
	initMessage := TraceToConformanceInitialize(data)
	initMsg := conformance.NewMessage(initMessage)
	initMsgBytes, err := jam.Marshal(initMsg)
	require.NoError(t, err)
	// Send the Initialize message
	err = handlers.WriteMessageWithContext(ctx, conn, initMsgBytes)
	require.NoError(t, err)
	// Read the response to the Initialize message
	initResponse, err := handlers.ReadMessageWithContext(ctx, conn)
	require.NoError(t, err)
	require.NotEmpty(t, initResponse)
	initRespMsg := &conformance.Message{}
	err = jam.Unmarshal(initResponse.Content, initRespMsg)
	require.NoError(t, err)
	require.NotNil(t, initRespMsg)

	// Send the ImportBlock message
	blockImportMessage := TraceToConformanceImportBlock(data)
	blockImportMsg := conformance.NewMessage(blockImportMessage)
	blockImportMsgBytes, err := jam.Marshal(blockImportMsg)
	require.NoError(t, err)
	err = handlers.WriteMessageWithContext(ctx, conn, blockImportMsgBytes)
	require.NoError(t, err)
	// Read the response to the ImportBlock message (StateRoot)
	importResponse, err := handlers.ReadMessageWithContext(ctx, conn)
	require.NoError(t, err)
	require.NotEmpty(t, importResponse)
	importRespMsg := &conformance.Message{}
	err = jam.Unmarshal(importResponse.Content, importRespMsg)
	require.NoError(t, err)
	require.NotNil(t, importRespMsg)

	// Create the GetState message to request the state
	headerHash, err := data.Block.Header.Hash()
	require.NoError(t, err)
	getStateMessage := CreateGetStateMessage(headerHash)
	getStateMsgBytes, err := jam.Marshal(getStateMessage)
	require.NoError(t, err)
	err = handlers.WriteMessageWithContext(ctx, conn, getStateMsgBytes)
	require.NoError(t, err)
	// Read the response to the GetState message (State)
	getStateResponse, err := handlers.ReadMessageWithContext(ctx, conn)
	require.NoError(t, err)
	require.NotEmpty(t, getStateResponse)
	getStateRespMsg := &conformance.Message{}
	err = jam.Unmarshal(getStateResponse.Content, getStateRespMsg)
	require.NoError(t, err)
	require.NotNil(t, getStateRespMsg)
	require.NotEmpty(t, getStateRespMsg.Get().(conformance.State).StateItems)

	// Restore state from the response
	keyValues := getStateRespMsg.Get().(conformance.State)
	require.NotEmpty(t, keyValues.StateItems)
	stateMap := KeyValueStateToStateMap(keyValues.StateItems)
	_, err = serialization.DeserializeState(stateMap)
	require.NoError(t, err, "failed to deserialize state")
}
