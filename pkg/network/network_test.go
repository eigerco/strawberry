package network_test

import (
	"context"
	"crypto/ed25519"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/eigerco/strawberry/pkg/network/cert"
	"github.com/eigerco/strawberry/pkg/network/handlers"
	"github.com/eigerco/strawberry/pkg/network/peer"
	"github.com/eigerco/strawberry/pkg/network/protocol"
	"github.com/eigerco/strawberry/pkg/network/transport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testNode represents a node instance for testing
type testNode struct {
	transport    *transport.Transport
	protoManager *protocol.Manager
	addr         string
	pubKey       ed25519.PublicKey
	privKey      ed25519.PrivateKey
}

// setupTestNode creates a new test node with all necessary components
func setupTestNode(t *testing.T) *testNode {
	// Find available port
	listener, err := net.Listen("tcp", "localhost:0")
	require.NoError(t, err)
	addr := listener.Addr().String()
	listener.Close()

	// Generate keys
	pub, priv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	// Create certificate
	certGen := cert.NewGenerator(cert.Config{
		PublicKey:          pub,
		PrivateKey:         priv,
		CertValidityPeriod: 24 * time.Hour,
	})
	tlsCert, err := certGen.GenerateCertificate()
	require.NoError(t, err)

	// Create protocol manager
	protoConfig := protocol.Config{
		ChainHash: "12345678",
		IsBuilder: false,
	}
	protoManager, err := protocol.NewManager(protoConfig)
	require.NoError(t, err)

	// Register handlers
	blockHandler := handlers.NewBlockRequestHandler()
	protoManager.Registry.RegisterHandler(protocol.StreamKindBlockRequest, blockHandler)

	// Create transport
	transportConfig := transport.Config{
		PublicKey:     pub,
		PrivateKey:    priv,
		TLSCert:       tlsCert,
		ListenAddr:    addr,
		CertValidator: cert.NewValidator(),
		Handler:       protoManager,
	}

	tr, err := transport.NewTransport(transportConfig)
	require.NoError(t, err)

	return &testNode{
		transport:    tr,
		protoManager: protoManager,
		addr:         addr,
		pubKey:       pub,
		privKey:      priv,
	}
}

// setupTestPair creates and connects two test nodes
func setupTestPair(t *testing.T) (*testNode, *testNode, *peer.Peer) {
	node1 := setupTestNode(t)
	node2 := setupTestNode(t)

	require.NoError(t, node1.transport.Start())
	require.NoError(t, node2.transport.Start())

	conn, err := node2.transport.Connect(node1.addr)
	require.NoError(t, err)

	p := peer.NewPeer(conn, conn.PeerKey(), node2.protoManager)
	return node1, node2, p
}

// Helper function to safely stop transports
func cleanupNodes(t *testing.T, nodes ...*testNode) {
	for _, node := range nodes {
		if err := node.transport.Stop(); err != nil {
			t.Errorf("failed to stop transport: %v", err)
		}
	}
}

// TestBasicBlockRequest tests a simple block request
func TestBasicBlockRequest(t *testing.T) {
	node1, node2, p := setupTestPair(t)
	defer cleanupNodes(t, node1, node2)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	response, err := p.RequestBlocks(ctx, [32]byte{1, 2, 3, 4}, true)
	require.NoError(t, err)
	assert.Equal(t, "test block response", string(response), "unexpected response content")
}

// TestConcurrentBlockRequests tests handling multiple concurrent requests
func TestConcurrentBlockRequests(t *testing.T) {
	node1, node2, p := setupTestPair(t)
	defer cleanupNodes(t, node1, node2)

	var wg sync.WaitGroup
	numRequests := 5
	type result struct {
		response []byte
		err      error
	}
	results := make(chan result, numRequests)

	for i := 0; i < numRequests; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			response, err := p.RequestBlocks(ctx, [32]byte{byte(i)}, true)
			results <- result{response, err}
		}(i)
	}

	wg.Wait()
	close(results)

	successCount := 0
	for res := range results {
		if assert.NoError(t, res.err) {
			assert.Equal(t, "test block response", string(res.response))
			successCount++
		}
	}
	assert.Equal(t, numRequests, successCount, "all requests should succeed")
}

// TestRequestTimeout tests proper handling of timeouts
func TestRequestTimeout(t *testing.T) {
	node1, node2, p := setupTestPair(t)
	defer cleanupNodes(t, node1, node2)

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Nanosecond)
	defer cancel()

	response, err := p.RequestBlocks(ctx, [32]byte{9, 9, 9, 9}, true)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), context.DeadlineExceeded.Error())
	assert.Nil(t, response)
}

// TestConnectionClosure tests behavior when connection is closed
func TestConnectionClosure(t *testing.T) {
	node1, node2, p := setupTestPair(t)
	defer cleanupNodes(t, node1, node2)

	// Close node1's transport
	require.NoError(t, node1.transport.Stop())

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	response, err := p.RequestBlocks(ctx, [32]byte{}, true)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), context.DeadlineExceeded.Error())
	assert.Nil(t, response)
}

// TestNetworkPartition tests behavior during network issues
func TestNetworkPartition(t *testing.T) {
	node1, node2, p := setupTestPair(t)
	defer cleanupNodes(t, node1, node2)

	// Simulate network partition by stopping node1
	require.NoError(t, node1.transport.Stop())

	// Start node1 again
	require.NoError(t, node1.transport.Start())

	// Try request after reconnection
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	_, err := p.RequestBlocks(ctx, [32]byte{1, 2, 3, 4}, true)
	assert.Error(t, err) // Should fail due to broken connection
}

// TestReconnection tests reconnection behavior
func TestServerNodeRestart(t *testing.T) {
	node1, node2, p := setupTestPair(t)
	defer cleanupNodes(t, node1, node2)

	// Make successful request
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	_, err := p.RequestBlocks(ctx, [32]byte{1}, true)
	cancel()
	require.NoError(t, err)

	// Close and restart node1's transport
	require.NoError(t, node1.transport.Stop())
	require.NoError(t, node1.transport.Start())

	conn, err := node2.transport.Connect(node1.addr)
	require.NoError(t, err)

	// Create new peer with new connection
	p = peer.NewPeer(conn, conn.PeerKey(), node2.protoManager)

	// Try request with longer timeout
	ctx, cancel = context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	res, err := p.RequestBlocks(ctx, [32]byte{1}, true)
	require.NoError(t, err)
	assert.Equal(t, "test block response", string(res))
}

func TestClientNodeRestart(t *testing.T) {
	node1, node2, p := setupTestPair(t)
	defer cleanupNodes(t, node1, node2)

	// Make initial successful request
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	response1, err := p.RequestBlocks(ctx, [32]byte{1, 2, 3, 4}, true)
	cancel()
	require.NoError(t, err)
	assert.Equal(t, "test block response", string(response1))

	// Close connection from node2 side
	require.NoError(t, node2.transport.Stop())

	// Restart node2
	require.NoError(t, node2.transport.Start())

	// Create new connection
	conn, err := node2.transport.Connect(node1.addr)
	require.NoError(t, err)

	// Create new peer with new connection
	newPeer := peer.NewPeer(conn, conn.PeerKey(), node2.protoManager)

	// Try request with new peer
	ctx, cancel = context.WithTimeout(context.Background(), time.Second)
	response2, err := newPeer.RequestBlocks(ctx, [32]byte{1, 2, 3, 4}, true)
	cancel()
	require.NoError(t, err)
	assert.Equal(t, "test block response", string(response2))
}
