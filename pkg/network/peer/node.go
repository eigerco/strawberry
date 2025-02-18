package peer

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/pkg/network/cert"
	"github.com/eigerco/strawberry/pkg/network/handlers"
	"github.com/eigerco/strawberry/pkg/network/protocol"
	"github.com/eigerco/strawberry/pkg/network/transport"
)

// Node manages peer connections, handles protocol messages, and coordinates network operations.
// Each Node can act as both a client and server, maintaining connections with multiple peers simultaneously.
type Node struct {
	Context         context.Context
	Cancel          context.CancelFunc
	transport       *transport.Transport
	protocolManager *protocol.Manager
	peersLock       sync.RWMutex
	peersSet        *PeerSet
	blockRequester  *handlers.BlockRequester
}

// ValidatorKeys holds the cryptographic keys required for a validator node.
// These keys are used for signing messages, participating in consensus,
// and establishing secure connections with other nodes.
type ValidatorKeys struct {
	EdPrv     ed25519.PrivateKey
	EdPub     ed25519.PublicKey
	BanderPrv crypto.BandersnatchPrivateKey
	BanderPub crypto.BandersnatchPublicKey
	Bls       crypto.BlsKey
}

// PeerSet maintains mappings between peer identifiers
// (Ed25519 keys, network addresses, validator indices) and Peer objects.
type PeerSet struct {
	// Map from Ed25519 public key to peer
	byEd25519Key map[string]*Peer
	// Map from string representation of address to peer
	byAddress map[string]*Peer
	// Map from validator index to peer (only for validator peers)
	byValidatorIndex map[uint16]*Peer
}

// NewPeerSet creates a new PeerSet instance with initialized internal maps.
func NewPeerSet() *PeerSet {
	return &PeerSet{
		byEd25519Key:     make(map[string]*Peer),
		byAddress:        make(map[string]*Peer),
		byValidatorIndex: make(map[uint16]*Peer),
	}
}

// AddPeer adds a peer to all relevant lookup maps in the PeerSet.
// If the peer is a validator index, it will also have a validator index.
func (ps *PeerSet) AddPeer(peer *Peer) {
	ps.byEd25519Key[string(peer.Ed25519Key)] = peer
	ps.byAddress[peer.Address.String()] = peer

	if peer.ValidatorIndex != nil {
		ps.byValidatorIndex[*peer.ValidatorIndex] = peer
	}
}

// RemovePeer removes a peer from all lookup maps in the PeerSet.
func (ps *PeerSet) RemovePeer(peer *Peer) {
	delete(ps.byEd25519Key, string(peer.Ed25519Key))
	delete(ps.byAddress, peer.Address.String())

	if peer.ValidatorIndex != nil {
		delete(ps.byValidatorIndex, *peer.ValidatorIndex)
	}
}

// GetByEd25519Key looks up a peer by their Ed25519 public key.
// Returns nil if no peer is found with the given key.
func (ps *PeerSet) GetByEd25519Key(key ed25519.PublicKey) *Peer {
	return ps.byEd25519Key[string(key)]
}

// GetByAddress looks up a peer by their network address.
// Returns nil if no peer is found with the given address.
func (ps *PeerSet) GetByAddress(addr string) *Peer {
	return ps.byAddress[addr]
}

// GetByValidatorIndex looks up a peer by their validator index.
// Returns nil if no peer is found with the given validator index.
func (ps *PeerSet) GetByValidatorIndex(index uint16) *Peer {
	return ps.byValidatorIndex[index]
}

// NewNode creates a new Node instance with the specified configuration.
// It initializes the TLS certificate, protocol manager, and network transport.
func NewNode(nodeCtx context.Context, listenAddr *net.UDPAddr, keys ValidatorKeys) (*Node, error) {
	nodeCtx, cancel := context.WithCancel(nodeCtx)
	node := &Node{
		peersSet: NewPeerSet(),
		Context:  nodeCtx,
		Cancel:   cancel,
	}

	// Create TLS certificate using the node's Ed25519 key pair
	certGen := cert.NewGenerator(cert.Config{
		PublicKey:          keys.EdPub,
		PrivateKey:         keys.EdPrv,
		CertValidityPeriod: 24 * time.Hour,
	})
	tlsCert, err := certGen.GenerateCertificate()
	if err != nil {
		return nil, fmt.Errorf("failed to generate certificate: %w", err)
	}

	// Initialize protocol manager with chain-specific configuration.
	// These are just testing values.
	protoConfig := protocol.Config{
		ChainHash:       "12345678",
		IsBuilder:       true,
		MaxBuilderSlots: 20,
	}
	protoManager, err := protocol.NewManager(protoConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create protocol manager: %w", err)
	}

	// Register what type of streams the Node will support.
	protoManager.Registry.RegisterHandler(protocol.StreamKindBlockRequest, handlers.NewBlockRequestHandler())

	// Create transport
	transportConfig := transport.Config{
		PublicKey:     keys.EdPub,
		PrivateKey:    keys.EdPrv,
		TLSCert:       tlsCert,
		ListenAddr:    listenAddr,
		CertValidator: cert.NewValidator(),
		Handler:       node,
		Context:       nodeCtx,
	}

	tr, err := transport.NewTransport(transportConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create transport: %w", err)
	}
	node.transport = tr
	node.protocolManager = protoManager
	return node, nil
}

// OnConnection is called by the transport layer whenever a new QUIC connection is established.
// This is a callback-style interface where transport.Conn represents an authenticated QUIC connection
// with a verified peer certificate. The connection flow is:
//
// 1. Transport layer accepts QUIC connection
// 2. TLS handshake completes, peer's Ed25519 key verified
// 3. Transport calls this OnConnection method
// 4. We check for existing connection from same peer
// 5. If exists: Close old connection (This will change soon), cleanup peer state.
// 6. Create protocol-level connection wrapper
// 7. Add new peer to connection registry
//
// This design separates transport-level connection handling (TLS, QUIC)
// from protocol-level peer management (stream handling, peer state).
func (n *Node) OnConnection(conn *transport.Conn) {
	n.peersLock.Lock()
	defer n.peersLock.Unlock()
	// If peer already exists, close existing connection and replace with new one.
	if existingPeer := n.peersSet.GetByEd25519Key(conn.PeerKey()); existingPeer != nil {
		// Close existing connection
		if err := existingPeer.ProtoConn.Close(); err != nil {
			log.Printf("Failed to close existing peer connection: %v", err)
		}
		n.peersSet.RemovePeer(existingPeer)
	}

	pConn := n.protocolManager.OnConnection(conn)
	peer := NewPeer(pConn)
	if peer == nil {
		log.Printf("Failed to create peer: invalid remote address type")
		// Clean up the connection since we can't use it
		if err := pConn.Close(); err != nil {
			log.Printf("Failed to close protocol connection: %v", err)
		}
		return
	}
	// Add to peer set
	n.peersSet.AddPeer(peer)
}

// ConnectToPeer initiates a connection to a peer at the specified address.
// It prevents duplicate connections to the same peer.
func (n *Node) ConnectToPeer(addr *net.UDPAddr) error {
	// Check if peer already exists before attempting connection.
	n.peersLock.RLock()
	existingPeer := n.peersSet.GetByAddress(addr.String())
	n.peersLock.RUnlock()

	if existingPeer != nil {
		return fmt.Errorf("peer already exists")
	}

	// Establish connection
	if err := n.transport.Connect(addr); err != nil {
		return fmt.Errorf("failed to connect to peer: %w", err)
	}
	return nil
}

// TODO somehwat of Mock atm. Will add full implementaion in the coming PR's.
func (n *Node) RequestBlock(ctx context.Context, hash crypto.Hash, ascending bool, peerKey ed25519.PublicKey) ([]byte, error) {
	n.peersLock.RLock()
	existingPeer := n.peersSet.GetByEd25519Key(peerKey)
	n.peersLock.RUnlock()

	if existingPeer != nil {
		stream, err := existingPeer.ProtoConn.OpenStream(ctx, protocol.StreamKindBlockRequest)
		if err != nil {
			return nil, fmt.Errorf("failed to open stream: %w", err)
		}

		defer stream.Close()
		blockData, err := n.blockRequester.RequestBlocks(ctx, stream, hash, ascending)
		if err != nil {
			return nil, fmt.Errorf("failed to request block from peer: %w", err)
		}
		return blockData, nil
	}
	return nil, fmt.Errorf("no peers available to request block from")
}

// Start begins the node's network operations, including listening for incoming connections.
func (n *Node) Start() error {
	if err := n.transport.Start(); err != nil {
		return fmt.Errorf("failed to start transport: %w", err)
	}
	return nil
}

// Stop gracefully shuts down the node's network operations and closes all
// peer connections.
func (n *Node) Stop() error {
	n.Cancel()
	return n.transport.Stop()
}

// ValidateConnection verifies that an incoming TLS connection meets the
// protocol requirements, including certificate validation and protocol
// version checking.
func (n *Node) ValidateConnection(tlsState tls.ConnectionState) error {
	return n.protocolManager.ValidateConnection(tlsState)
}

// GetProtocols returns the list of supported protocol
// versions and variants for this node.
func (n *Node) GetProtocols() []string {
	return n.protocolManager.GetProtocols()
}
