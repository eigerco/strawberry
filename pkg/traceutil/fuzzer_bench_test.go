//go:build tiny

package traceutil

import (
	"context"
	"net"
	"testing"

	"github.com/eigerco/strawberry/pkg/conformance"
	"github.com/eigerco/strawberry/pkg/network/handlers"
	"github.com/eigerco/strawberry/pkg/serialization/codec/jam"
	"github.com/stretchr/testify/require"
)

func BenchmarkTestVectorFileWithGenesis(b *testing.B) {
	// Parse the trace vector
	b.Skip("This is used for manual testing with a local jam target")
	genesis, err := ParseGenesisFile(b, "genesis.bin")
	require.NoError(b, err)
	require.NotEmpty(b, genesis)
	block, err := ParseTraceFile(b, "00000001.bin")
	require.NoError(b, err)
	require.NotEmpty(b, block)

	// Create a connection and first message (PeerInfo)
	peerInfoMessage := CreatePeerInfoMessage()
	conn, err := net.Dial("unix", "/tmp/jam_target.sock")
	require.NoError(b, err)
	defer func() {
		require.NoError(b, conn.Close())
	}()
	msgBytes, err := jam.Marshal(peerInfoMessage)
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

	b.ResetTimer() // Reset timer after setup

	for i := 0; i < b.N; i++ {
		// Create the Initialize message (Prestate)
		initMessage := GenesisToConformanceInitialize(genesis)
		initMsg := conformance.NewMessage(initMessage)
		initMsgBytes, err := jam.Marshal(initMsg)
		require.NoError(b, err)
		// Send the Initialize message
		err = handlers.WriteMessageWithContext(ctx, conn, initMsgBytes)
		require.NoError(b, err)
		// Read the response to the Initialize message
		initResponse, err := handlers.ReadMessageWithContext(ctx, conn)
		require.NoError(b, err)
		require.NotEmpty(b, initResponse)
		initRespMsg := &conformance.Message{}
		err = jam.Unmarshal(initResponse.Content, initRespMsg)
		require.NoError(b, err)
		require.NotNil(b, initRespMsg)

		// Send the ImportBlock message
		blockImportMessage := TraceToConformanceImportBlock(block)
		blockImportMsg := conformance.NewMessage(blockImportMessage)
		blockImportMsgBytes, err := jam.Marshal(blockImportMsg)
		require.NoError(b, err)
		err = handlers.WriteMessageWithContext(ctx, conn, blockImportMsgBytes)
		require.NoError(b, err)
		// Read the response to the ImportBlock message (StateRoot)
		importResponse, err := handlers.ReadMessageWithContext(ctx, conn)
		require.NoError(b, err)
		require.NotEmpty(b, importResponse)
		importRespMsg := &conformance.Message{}
		err = jam.Unmarshal(importResponse.Content, importRespMsg)
		require.NoError(b, err)
		require.NotNil(b, importRespMsg)
	}
}

func BenchmarkTestVectorFileOnly(b *testing.B) {
	// Parse the trace vector
	b.Skip("This is used for manual testing with a local jam target")
	data, err := ParseTraceFile(b, "00000001.bin")
	require.NoError(b, err)
	require.NotEmpty(b, data)

	// Create a connection and first message (PeerInfo)
	peerInfoMessage := CreatePeerInfoMessage()
	conn, err := net.Dial("unix", "/tmp/jam_target.sock")
	require.NoError(b, err)
	defer func() {
		require.NoError(b, conn.Close())
	}()
	msgBytes, err := jam.Marshal(peerInfoMessage)
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

	b.ResetTimer() // Reset timer after setup

	for i := 0; i < b.N; i++ {
		// Create the Initialize message (Prestate)
		initMessage := TraceToConformanceInitialize(data)
		initMsg := conformance.NewMessage(initMessage)
		initMsgBytes, err := jam.Marshal(initMsg)
		require.NoError(b, err)
		// Send the Initialize message
		err = handlers.WriteMessageWithContext(ctx, conn, initMsgBytes)
		require.NoError(b, err)
		// Read the response to the Initialize message
		initResponse, err := handlers.ReadMessageWithContext(ctx, conn)
		require.NoError(b, err)
		require.NotEmpty(b, initResponse)
		initRespMsg := &conformance.Message{}
		err = jam.Unmarshal(initResponse.Content, initRespMsg)
		require.NoError(b, err)
		require.NotNil(b, initRespMsg)

		// Send the ImportBlock message
		blockImportMessage := TraceToConformanceImportBlock(data)
		blockImportMsg := conformance.NewMessage(blockImportMessage)
		blockImportMsgBytes, err := jam.Marshal(blockImportMsg)
		require.NoError(b, err)
		err = handlers.WriteMessageWithContext(ctx, conn, blockImportMsgBytes)
		require.NoError(b, err)
		// Read the response to the ImportBlock message (StateRoot)
		importResponse, err := handlers.ReadMessageWithContext(ctx, conn)
		require.NoError(b, err)
		require.NotEmpty(b, importResponse)
		importRespMsg := &conformance.Message{}
		err = jam.Unmarshal(importResponse.Content, importRespMsg)
		require.NoError(b, err)
		require.NotNil(b, importRespMsg)
	}
}
