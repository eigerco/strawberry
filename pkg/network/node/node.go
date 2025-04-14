package node

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/eigerco/strawberry/internal/block"
	"github.com/eigerco/strawberry/internal/chain"
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/state"
	"github.com/eigerco/strawberry/internal/statetransition"
	"github.com/eigerco/strawberry/internal/validator"
	"github.com/eigerco/strawberry/internal/work"
	"github.com/eigerco/strawberry/pkg/network/cert"
	"github.com/eigerco/strawberry/pkg/network/handlers"
	"github.com/eigerco/strawberry/pkg/network/peer"
	"github.com/eigerco/strawberry/pkg/network/protocol"
	"github.com/eigerco/strawberry/pkg/network/transport"
)

// Node manages peer connections, handles protocol messages, and coordinates network operations.
// Each Node can act as both a client and server, maintaining connections with multiple peers simultaneously.
type Node struct {
	Context               context.Context
	Cancel                context.CancelFunc
	ValidatorManager      *validator.ValidatorManager
	BlockService          *chain.BlockService
	ProtocolManager       *protocol.Manager
	PeersSet              *PeerSet
	peersLock             sync.RWMutex
	transport             *transport.Transport
	State                 state.State
	blockRequester        *handlers.BlockRequester
	workPackageSubmitter  *handlers.WorkPackageSubmitter
	auditShardSender      *handlers.AuditShardRequestSender
	shardDistributor      *handlers.ShardDistributionSender
	workPackageSharer     *handlers.WorkPackageSharer
	currentCoreIndex      uint16
	currentGuarantorPeers []*peer.Peer
}

// PeerSet maintains mappings between peer identifiers
// (Ed25519 keys, network addresses, validator indices) and Peer objects.
type PeerSet struct {
	// Map from Ed25519 public key to peer
	byEd25519Key map[string]*peer.Peer
	// Map from string representation of address to peer
	byAddress map[string]*peer.Peer
	// Map from validator index to peer (only for validator peers)
	byValidatorIndex map[uint16]*peer.Peer
}

// NewPeerSet creates a new PeerSet instance with initialized internal maps.
func NewPeerSet() *PeerSet {
	return &PeerSet{
		byEd25519Key:     make(map[string]*peer.Peer),
		byAddress:        make(map[string]*peer.Peer),
		byValidatorIndex: make(map[uint16]*peer.Peer),
	}
}

// AddPeer adds a peer to all relevant lookup maps in the PeerSet.
// If the peer is a validator index, it will also have a validator index.
func (ps *PeerSet) AddPeer(peer *peer.Peer) {
	ps.byEd25519Key[string(peer.Ed25519Key)] = peer
	ps.byAddress[peer.Address.String()] = peer

	if peer.ValidatorIndex != nil {
		ps.byValidatorIndex[*peer.ValidatorIndex] = peer
	}
}

// RemovePeer removes a peer from all lookup maps in the PeerSet.
func (ps *PeerSet) RemovePeer(peer *peer.Peer) {
	delete(ps.byEd25519Key, string(peer.Ed25519Key))
	delete(ps.byAddress, peer.Address.String())

	if peer.ValidatorIndex != nil {
		delete(ps.byValidatorIndex, *peer.ValidatorIndex)
	}
}

// GetByEd25519Key looks up a peer by their Ed25519 public key.
// Returns nil if no peer is found with the given key.
func (ps *PeerSet) GetByEd25519Key(key ed25519.PublicKey) *peer.Peer {
	return ps.byEd25519Key[string(key)]
}

// GetByAddress looks up a peer by their network address.
// Returns nil if no peer is found with the given address.
func (ps *PeerSet) GetByAddress(addr string) *peer.Peer {
	return ps.byAddress[addr]
}

// GetByValidatorIndex looks up a peer by their validator index.
// Returns nil if no peer is found with the given validator index.
func (ps *PeerSet) GetByValidatorIndex(index uint16) *peer.Peer {
	return ps.byValidatorIndex[index]
}

// NewNode creates a new Node instance with the specified configuration.
// It initializes the TLS certificate, protocol manager, and network transport.
func NewNode(nodeCtx context.Context, listenAddr *net.UDPAddr, keys validator.ValidatorKeys, state state.State, validatorIdx uint16) (*Node, error) {
	nodeCtx, cancel := context.WithCancel(nodeCtx)
	node := &Node{
		PeersSet: NewPeerSet(),
		State:    state,
		Context:  nodeCtx,
		Cancel:   cancel,
	}
	node.ValidatorManager = validator.NewValidatorManager(keys, state.ValidatorState, validatorIdx)

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

	// Create block service
	bs, err := chain.NewBlockService()
	if err != nil {
		return nil, fmt.Errorf("failed to create block service: %w", err)
	}

	protoManager, err := protocol.NewManager(protoConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create protocol manager: %w", err)
	}

	// Register what type of streams the Node will support.
	protoManager.Registry.RegisterHandler(protocol.StreamKindBlockRequest, handlers.NewBlockRequestHandler(bs))
	protoManager.Registry.RegisterHandler(protocol.StreamKindBlockAnnouncement, handlers.NewBlockAnnouncementHandler(bs, node))

	node.blockRequester = &handlers.BlockRequester{}

	wpSharerHandler := handlers.NewWorkPackageSharer()
	node.workPackageSharer = wpSharerHandler

	protoManager.Registry.RegisterHandler(protocol.StreamKindWorkPackageSubmit, handlers.NewWorkPackageSubmissionHandler(&handlers.ImportSegments{}, wpSharerHandler))
	submitter := &handlers.WorkPackageSubmitter{}
	node.workPackageSubmitter = submitter

	validatorSvc := validator.NewService()
	protoManager.Registry.RegisterHandler(protocol.StreamKindShardDist, handlers.NewShardDistributionHandler(validatorSvc))
	protoManager.Registry.RegisterHandler(protocol.StreamKindAuditShardRequest, handlers.NewAuditShardRequestHandler(validatorSvc))

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

	node.BlockService = bs
	node.transport = tr
	node.ProtocolManager = protoManager
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
	if existingPeer := n.PeersSet.GetByEd25519Key(conn.PeerKey()); existingPeer != nil {
		// Close existing connection
		if err := existingPeer.ProtoConn.Close(); err != nil {
			log.Printf("Failed to close existing peer connection: %v", err)
		}
		n.PeersSet.RemovePeer(existingPeer)
	}

	pConn := n.ProtocolManager.OnConnection(conn)
	peer := peer.NewPeer(pConn)
	if peer == nil {
		log.Printf("Failed to create peer: invalid remote address type")
		// Clean up the connection since we can't use it
		if err := pConn.Close(); err != nil {
			log.Printf("Failed to close protocol connection: %v", err)
		}
		return
	}

	// Add to peer set
	n.PeersSet.AddPeer(peer)
}

// ConnectToPeer initiates a connection to a peer at the specified address.
// It prevents duplicate connections to the same peer.
func (n *Node) ConnectToPeer(addr *net.UDPAddr) error {
	// Check if peer already exists before attempting connection.
	n.peersLock.RLock()
	existingPeer := n.PeersSet.GetByAddress(addr.String())
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

// ConnectToNeighbours connects to all neighbor validators according to the
// grid structure defined in the JAMNP
func (n *Node) ConnectToNeighbours() error {
	neighbors, err := n.ValidatorManager.GetNeighbors()
	if err != nil {
		return fmt.Errorf("failed to get neighbors: %w", err)
	}
	for _, neighbor := range neighbors {
		// Extract IPv6/port from validator metadata as specified in the JAMNP
		address, err := peer.NewPeerAddressFromMetadata(neighbor.Metadata[:])
		if err != nil {
			return err
		}
		if err := n.ConnectToPeer(address); err != nil {
			return fmt.Errorf("failed to connect to neighbor: %w", err)
		}
	}
	return nil
}

// RequestBlocks implements the CE 128 block request protocol from the JAM spec.
// It requests one or more blocks from a peer, starting with the block identified
// by the given hash. The direction can be ascending (child blocks) or descending
// (parent blocks), with a maximum number of blocks to return.
func (n *Node) RequestBlocks(ctx context.Context, hash crypto.Hash, ascending bool, maxBlocks uint32, peerKey ed25519.PublicKey) ([]block.Block, error) {
	n.peersLock.RLock()
	defer n.peersLock.RUnlock()

	if existingPeer := n.PeersSet.GetByEd25519Key(peerKey); existingPeer != nil {
		stream, err := existingPeer.ProtoConn.OpenStream(ctx, protocol.StreamKindBlockRequest)
		if err != nil {
			return nil, fmt.Errorf("failed to open stream: %w", err)
		}

		defer stream.Close()
		blocks, err := n.blockRequester.RequestBlocks(ctx, stream, hash, ascending, maxBlocks)
		if err != nil {
			return nil, fmt.Errorf("failed to request block from peer: %w", err)
		}
		return blocks, nil
	}
	return nil, fmt.Errorf("no peers available to request block from")
}

// SubmitWorkPackage implements the CE 133 work package submission protocol from the JAMNP.
// It allows a builder node to submit a work package to a guarantor for processing.
// The submission includes the core index, work package, and extrinsic data.
func (n *Node) SubmitWorkPackage(ctx context.Context, coreIndex uint16, pkg work.Package, extrinsics []byte, peerKey ed25519.PublicKey) error {
	n.peersLock.RLock()
	defer n.peersLock.RUnlock()

	peer := n.PeersSet.GetByEd25519Key(peerKey)
	if peer == nil {
		return fmt.Errorf("no peer available for submission with the given key")
	}

	stream, err := peer.ProtoConn.OpenStream(ctx, protocol.StreamKindWorkPackageSubmit)
	if err != nil {
		return fmt.Errorf("failed to open submission stream: %w", err)
	}

	if err = n.workPackageSubmitter.SubmitWorkPackage(ctx, stream, coreIndex, pkg, extrinsics); err != nil {
		return fmt.Errorf("failed to submit work package: %w", err)
	}
	return nil
}

// ShardDistributionSend implements the sending side of the CE 137, it opens a connection to the provided peer
// allowing the assurers request shards from the guarantor
func (n *Node) ShardDistributionSend(ctx context.Context, peerKey ed25519.PublicKey, erasureRoot crypto.Hash, shardIndex uint16) (bundleShard []byte, segmentShard [][]byte, justification [][]byte, err error) {
	n.peersLock.RLock()
	defer n.peersLock.RUnlock()

	peer := n.PeersSet.GetByEd25519Key(peerKey)
	if peer == nil {
		return nil, nil, nil, fmt.Errorf("no peer available for shard distribution with the given key")
	}

	stream, err := peer.ProtoConn.OpenStream(ctx, protocol.StreamKindShardDist)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to open shard distribution stream: %w", err)
	}

	bundleShard, segmentShard, justification, err = n.shardDistributor.ShardDistribution(ctx, stream, erasureRoot, shardIndex)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to request shards: %w", err)
	}
	return bundleShard, segmentShard, justification, nil
}

// AuditShardRequestSend implements the sending side of the CE 138, it opens a connection to the provided peer
// allowing the auditors to request shards from the assurer
func (n *Node) AuditShardRequestSend(ctx context.Context, peerKey ed25519.PublicKey, erasureRoot crypto.Hash, shardIndex uint16) (bundleShard []byte, justification [][]byte, err error) {
	n.peersLock.RLock()
	defer n.peersLock.RUnlock()

	peer := n.PeersSet.GetByEd25519Key(peerKey)
	if peer == nil {
		return nil, nil, fmt.Errorf("no peer available for audit shard with the given key")
	}

	stream, err := peer.ProtoConn.OpenStream(ctx, protocol.StreamKindAuditShardRequest)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to open audit shard request stream: %w", err)
	}

	bundleShard, justification, err = n.auditShardSender.AuditShardRequest(ctx, stream, erasureRoot, shardIndex)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to request shards: %w", err)
	}
	return bundleShard, justification, nil
}

// UpdateCoreAssignments updates both the current core of this node and the co-guarantors (other validators assigned to the same core).
// Each validator is assigned to exactly one core per rotation period, and every core is backed by 3 unique validators.
//
// Assignment follows the process defined in the Guarantor Assignment section (11.3):
// 1. Create a core assignment sequence by evenly mapping validators to cores
// 2. Shuffle the sequence deterministically using the epochal entropy η2 (for the current epoch guarantors)
// 3. Apply a rotation offset based on the current timeslot (every 10 blocks)
// 4. Update our local node’s core index via assignments
// 5. Identify and register other validators who share that same core and update workPackageSharer handler for CE-134
// TODO: Call this during node initialization and periodically to keep core and co-guarantors up to date.
func (n *Node) UpdateCoreAssignments() error {
	assignments, err := statetransition.PermuteAssignments(n.State.EntropyPool[2], n.State.TimeslotIndex)
	if err != nil {
		return fmt.Errorf("failed to permute validator assignments: %w", err)
	}

	coreIndex := uint16(assignments[n.ValidatorManager.Index])

	n.peersLock.Lock()
	defer n.peersLock.Unlock()

	var peers []*peer.Peer
	for validatorIdx, core := range assignments {
		if core == uint32(coreIndex) && uint16(validatorIdx) != n.ValidatorManager.Index {
			p := n.PeersSet.GetByValidatorIndex(uint16(validatorIdx))
			if p == nil {
				return fmt.Errorf("peer with validator index %d not found", validatorIdx)
			}
			peers = append(peers, p)
		}
	}

	n.currentCoreIndex = coreIndex

	n.currentGuarantorPeers = peers
	n.workPackageSharer.SetGuarantors(peers)

	return nil
}

// AnnounceBlock implements the UP 0 block announcement protocol from the JAM spec.
// It announces a new block to a peer by sending the block header. The announcement
// also includes the latest finalized block information as required by the protocol.
func (n *Node) AnnounceBlock(ctx context.Context, header *block.Header, peer *peer.Peer) error {
	// If we already have an announcer for this peer, use it
	if peer.BAnnouncer != nil {
		return peer.BAnnouncer.SendAnnouncement(header)
	}

	handler, err := peer.ProtoConn.Registry.GetHandler(protocol.StreamKindBlockAnnouncement)
	if err != nil {
		return fmt.Errorf("failed to get announcement handler: %w", err)
	}

	// Type assert to get the BlockAnnouncementHandler
	bah, ok := handler.(*handlers.BlockAnnouncementHandler)
	if !ok {
		return fmt.Errorf("invalid handler type for block announcements")
	}
	// Check if we already have an announcer for this peer in BlockAnnouncementHandler. This should never happen.
	announcer, ok := bah.Announcers[string(peer.ProtoConn.TConn.PeerKey())]
	if ok {
		peer.BAnnouncer = announcer
		return announcer.SendAnnouncement(header)
	} else { //For sure we dont have an announcer for this peer
		stream, err := peer.ProtoConn.OpenStream(ctx, protocol.StreamKindBlockAnnouncement)
		if err != nil {
			return fmt.Errorf("open stream: %w", err)
		}

		peer.BAnnouncer = bah.NewBlockAnnouncer(n.BlockService, peer.ProtoConn.TConn.Context(), stream, peer.ProtoConn.TConn.PeerKey())
		// this will handle handshake
		errCh := make(chan error, 1)
		go func() {
			errCh <- peer.BAnnouncer.Start()
		}()

		// Wait for either handshake completion or error
		select {
		case err := <-errCh:
			if err != nil {
				stream.Close()
				return fmt.Errorf("failed to start announcement handler: %w", err)
			}
		case <-ctx.Done():
			stream.Close()
			return ctx.Err()
		}
		return peer.BAnnouncer.SendAnnouncement(header)
	}
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
	return n.ProtocolManager.ValidateConnection(tlsState)
}

// GetProtocols returns the list of supported protocol
// versions and variants for this node.
func (n *Node) GetProtocols() []string {
	return n.ProtocolManager.GetProtocols()
}
