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

	"github.com/eigerco/strawberry/internal/authorization"
	"github.com/eigerco/strawberry/internal/block"
	"github.com/eigerco/strawberry/internal/chain"
	"github.com/eigerco/strawberry/internal/common"
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/d3l"
	"github.com/eigerco/strawberry/internal/refine"
	"github.com/eigerco/strawberry/internal/state"
	"github.com/eigerco/strawberry/internal/statetransition"
	"github.com/eigerco/strawberry/internal/store"
	"github.com/eigerco/strawberry/internal/validator"
	"github.com/eigerco/strawberry/internal/work"
	"github.com/eigerco/strawberry/pkg/db/pebble"
	"github.com/eigerco/strawberry/pkg/network/cert"
	"github.com/eigerco/strawberry/pkg/network/handlers"
	"github.com/eigerco/strawberry/pkg/network/peer"
	"github.com/eigerco/strawberry/pkg/network/protocol"
	"github.com/eigerco/strawberry/pkg/network/transport"
)

// Node manages peer connections, handles protocol messages, and coordinates network operations.
// Each Node can act as both a client and server, maintaining connections with multiple peers simultaneously.
type Node struct {
	Context                       context.Context
	Cancel                        context.CancelFunc
	ValidatorManager              *validator.ValidatorManager
	BlockService                  *chain.BlockService
	ProtocolManager               *protocol.Manager
	PeersSet                      *peer.PeerSet
	peersLock                     sync.RWMutex
	transport                     *transport.Transport
	State                         state.State
	blockRequester                *handlers.BlockRequester
	workPackageSubmitter          *handlers.WorkPackageSubmitter
	auditShardSender              *handlers.AuditShardRequestSender
	shardDistributor              *handlers.ShardDistributionSender
	segmentShardRequestSender     *handlers.SegmentShardRequestSender
	segmentShardRequestJustSender *handlers.SegmentShardRequestJustificationSender
	stateReqester                 *handlers.StateRequester
	WorkReportGuarantor           handlers.WorkReportProcessAndGuarantee
	workReportRequester           *handlers.WorkReportRequester
	WorkPackageSharingHandler     *handlers.WorkPackageSharingHandler
	safroleTicketSubmiter         *handlers.SafroleTicketSubmiter
	currentCoreIndex              uint16
	currentGuarantorPeers         []*peer.Peer
	ValidatorService              validator.ValidatorService
	StateTrieStore                *store.Trie
	AvailabilityStore             *store.Shards
	TicketStore                   *store.Ticket
	SegmentRootToErasureRoot      map[crypto.Hash]crypto.Hash
	SegmentRootLookup             work.SegmentRootLookup
}

func (n *Node) GetAllPeers() []*peer.Peer {
	n.peersLock.RLock()
	defer n.peersLock.RUnlock()
	return n.PeersSet.GetAllPeers()
}

// NewNode creates a new Node instance with the specified configuration.
// It initializes the TLS certificate, protocol manager, and network transport.
func NewNode(nodeCtx context.Context, listenAddr *net.UDPAddr, keys validator.ValidatorKeys, state state.State, validatorIdx uint16) (*Node, error) {
	kvStore, err := pebble.NewKVStore()
	if err != nil {
		return nil, err
	}

	availabilityStore := store.NewShards(kvStore)
	nodeCtx, cancel := context.WithCancel(nodeCtx)
	peerSet := peer.NewPeerSet()
	node := &Node{
		PeersSet:                 peerSet,
		State:                    state,
		Context:                  nodeCtx,
		Cancel:                   cancel,
		ValidatorService:         validator.NewService(availabilityStore),
		AvailabilityStore:        availabilityStore,
		StateTrieStore:           store.NewTrie(kvStore),
		TicketStore:              store.NewTicket(kvStore),
		SegmentRootToErasureRoot: make(map[crypto.Hash]crypto.Hash), // TODO compute from state history
		SegmentRootLookup:        make(map[crypto.Hash]crypto.Hash), // TODO compute from state history
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
	bs, err := chain.NewBlockService(kvStore)
	if err != nil {
		return nil, fmt.Errorf("failed to create block service: %w", err)
	}

	protoManager, err := protocol.NewManager(protoConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create protocol manager: %w", err)
	}

	// Register what type of streams the Node will support.
	protoManager.Registry.RegisterHandler(protocol.StreamKindBlockRequest, handlers.NewBlockRequestHandler(bs))
	announcementHandler := handlers.NewBlockAnnouncementHandler(bs, node)

	// Assurance hook, triggers the assurance process for the newly added guarantees from the block extrinsic (EG)
	// iterates over each guarantee and requests the shards with self validator index
	// from the validators identified in the guarantee extrinsic
	announcementHandler.AddOnBlockReceiveHook(node.onBlockReceivedDistributeShards)

	protoManager.Registry.RegisterHandler(protocol.StreamKindBlockAnnouncement, announcementHandler)

	node.blockRequester = &handlers.BlockRequester{}

	wrStore := store.NewWorkReport(kvStore)

	node.workReportRequester = handlers.NewWorkReportRequester()

	protoManager.Registry.RegisterHandler(protocol.StreamKindWorkReportRequest, handlers.NewWorkReportRequestHandler(wrStore))

	authInvocation := authorization.New(state)
	refineInvocation := refine.New(state)

	wpSharerHandler := handlers.NewWorkReportGuarantor(
		validatorIdx,
		keys.EdPrv,
		authInvocation,
		refineInvocation,
		state,
		peerSet,
		wrStore,
		node.workReportRequester,
		handlers.NewWorkPackageSharingRequester(),
		handlers.NewWorkReportDistributionSender(),
		node.ValidatorService,
		node.SegmentRootLookup,
	)
	node.WorkReportGuarantor = wpSharerHandler

	protoManager.Registry.RegisterHandler(protocol.StreamKindWorkPackageSubmit, handlers.NewWorkPackageSubmissionHandler(
		d3l.NewSegmentsFetcher(node, node.SegmentRootToErasureRoot),
		node.WorkReportGuarantor,
		node.SegmentRootLookup,
	))
	submitter := &handlers.WorkPackageSubmitter{}
	node.workPackageSubmitter = submitter

	node.WorkPackageSharingHandler = handlers.NewWorkPackageSharingHandler(authInvocation, refineInvocation, keys.EdPrv, state.Services, wrStore, node.ValidatorService)
	protoManager.Registry.RegisterHandler(protocol.StreamKindWorkPackageShare, node.WorkPackageSharingHandler)

	protoManager.Registry.RegisterHandler(protocol.StreamKindWorkReportDist, handlers.NewWorkReportDistributionHandler())

	protoManager.Registry.RegisterHandler(protocol.StreamKindShardDist, handlers.NewShardDistributionHandler(node.ValidatorService))
	protoManager.Registry.RegisterHandler(protocol.StreamKindAuditShardRequest, handlers.NewAuditShardRequestHandler(node.ValidatorService))
	protoManager.Registry.RegisterHandler(protocol.StreamKindSegmentRequest, handlers.NewSegmentShardRequestHandler(node.ValidatorService))
	protoManager.Registry.RegisterHandler(protocol.StreamKindSegmentRequestJust, handlers.NewSegmentShardRequestJustificationHandler(node.ValidatorService))

	node.stateReqester = &handlers.StateRequester{}
	protoManager.Registry.RegisterHandler(protocol.StreamKindStateRequest, handlers.NewStateRequestHandler(node.StateTrieStore))

	// Safrole ticket submission and broadcast handlers

	node.safroleTicketSubmiter = &handlers.SafroleTicketSubmiter{}
	// Register handler for safrole ticket submission to proxy (CE131)
	protoManager.Registry.RegisterHandler(protocol.StreamKindSafroleTicketSubmit, handlers.NewSafroleTicketSubmitRequestHandler(&state, node.ValidatorManager, node.TicketStore))
	// Register handler for safrole ticket broadcast to proxy (CE132)
	protoManager.Registry.RegisterHandler(protocol.StreamKindSafroleTicketDist, handlers.NewSafroleTicketBroadcastRequestHandler(&state, node.ValidatorManager, node.TicketStore))

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

// RequestWorkReport implements the CE 136 work-report request protocol from the JAM spec.
// It requests a work report from a peer identified by the given hash.
func (n *Node) RequestWorkReport(ctx context.Context, hash crypto.Hash, peerKey ed25519.PublicKey) (*block.WorkReport, error) {
	n.peersLock.RLock()
	defer n.peersLock.RUnlock()

	if existingPeer := n.PeersSet.GetByEd25519Key(peerKey); existingPeer != nil {
		stream, err := existingPeer.ProtoConn.OpenStream(ctx, protocol.StreamKindWorkReportRequest)
		if err != nil {
			return nil, fmt.Errorf("failed to open stream: %w", err)
		}

		report, err := n.workReportRequester.RequestWorkReport(ctx, stream, hash)
		if err != nil {
			return nil, fmt.Errorf("failed to request work report from peer: %w", err)
		}
		return report, nil
	}
	return nil, fmt.Errorf("no peers available to request work report from")
}

// ShardDistributionSend implements the sending side of the CE 137, it opens a connection to the provided peer
// allowing the assurers request shards from the guarantor
func (n *Node) ShardDistributionSend(ctx context.Context, peerKey ed25519.PublicKey, coreIndex uint16, erasureRoot crypto.Hash) (bundleShard []byte, segmentShard [][]byte, justification [][]byte, err error) {
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

	shardIndex := n.assignedShardIndex(coreIndex, n.ValidatorManager.Index)

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

// SegmentShardRequestSend implements the sending side of the CE 139 protocol, opens a connection between
// the guarantor and assurer allowing the guarantor to reconstruct the segments
func (n *Node) SegmentShardRequestSend(ctx context.Context, peerKey ed25519.PublicKey, erasureRoot crypto.Hash, shardIndex uint16, segmentIndexes []uint16) (segmentShards [][]byte, err error) {
	n.peersLock.RLock()
	defer n.peersLock.RUnlock()

	peer := n.PeersSet.GetByEd25519Key(peerKey)
	if peer == nil {
		return nil, fmt.Errorf("no peer available for audit shard with the given key")
	}

	stream, err := peer.ProtoConn.OpenStream(ctx, protocol.StreamKindSegmentRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to open audit shard request stream: %w", err)
	}

	segmentShards, err = n.segmentShardRequestSender.SegmentShardRequest(ctx, stream, erasureRoot, shardIndex, segmentIndexes)
	if err != nil {
		return nil, fmt.Errorf("failed to request shards: %w", err)
	}
	return segmentShards, nil
}

// SegmentShardRequestJustificationSend implements the sending side of the CE 140 protocol, opens a connection between
// the guarantor and assurer allowing the guarantor to reconstruct the segments and to immediately assess the correctness of the response.
func (n *Node) SegmentShardRequestJustificationSend(ctx context.Context, peerKey ed25519.PublicKey, erasureRoot crypto.Hash, shardIndex uint16, segmentIndexes []uint16) (segmentShards [][]byte, justification [][][]byte, err error) {
	n.peersLock.RLock()
	defer n.peersLock.RUnlock()

	peer := n.PeersSet.GetByEd25519Key(peerKey)
	if peer == nil {
		return nil, nil, fmt.Errorf("no peer available for audit shard with the given key")
	}

	stream, err := peer.ProtoConn.OpenStream(ctx, protocol.StreamKindSegmentRequestJust)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to open audit shard request stream: %w", err)
	}

	segmentShards, justification, err = n.segmentShardRequestJustSender.SegmentShardRequestJustification(ctx, stream, erasureRoot, shardIndex, segmentIndexes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to request shards with justification: %w", err)
	}
	return segmentShards, justification, nil
}

// UpdateCoreAssignments updates both the current core of this node and the co-guarantors (other validators assigned to the same core).
// Each validator is assigned to exactly one core per rotation period, and every core is backed by 3 unique validators.
//
// Assignment follows the process defined in the Guarantor Assignment section (11.3):
// 1. Create a core assignment sequence by evenly mapping validators to cores
// 2. Shuffle the sequence deterministically using the epochal entropy η2 (for the current epoch guarantors)
// 3. Apply a rotation offset based on the current timeslot (every 10 blocks)
// 4. Update our local node’s core index via assignments
// 5. Identify and register other validators who share that same core and update WorkReportGuarantor handler for CE-134
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
	n.WorkPackageSharingHandler.SetCurrentCore(n.currentCoreIndex)

	n.currentGuarantorPeers = peers
	n.WorkReportGuarantor.SetGuarantors(peers)

	return nil
}

// assignedShardIndex computes the shard index `i` assigned to a validator `v` for a given core `c`.
//
// Based on the network spec the shard assignment is defined as:
//
//	i = (c * R + v) mod V
//
// Where:
//   - v = index of a validator
//   - i = shard index assigned to the validator
//   - c = core index that produced the work-report
//   - R = recovery threshold: the minimum number of EC shards required to recover the original data
//   - V = total number of validators
func (n *Node) assignedShardIndex(coreIndex, validatorIndex uint16) uint16 {
	return (coreIndex*uint16(common.ErasureCodingOriginalShards) + validatorIndex) % common.NumberOfValidators
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

// RequestState implements the client side of the CE 129 State Request protocol from the JAMNP.
// It requests a range of key-value pairs from a block's posterior state from a peer node.
//
// The method finds the specified peer by its Ed25519 public key, opens a stream for a state request,
// and uses the StateRequester to fetch the state data. The response includes boundary nodes
// (which form a Merkle proof path) and the requested key-value pairs from the state trie.
//
// Parameters:
//   - ctx: Context for the request, used for cancellation and timeouts
//   - headerHash: Hash of the block header whose state is being requested
//   - keyStart: First key in the requested range (inclusive, 31 bytes)
//   - keyEnd: Last key in the requested range (inclusive, 31 bytes)
//   - maxSize: Maximum size in bytes for the response
//   - peerKey: Ed25519 public key of the peer to request state from
//
// Returns:
//   - A TrieRangeResult containing boundary nodes (for Merkle verification) and key-value pairs
//   - An error if the request fails or no peer is found with the given key
//
// Key = [u8; 31] (First 31 bytes of key only)
// Maximum Size = u32
// Boundary Node = As returned by B/L, defined in the State Merklization appendix of the GP
// Value = len++[u8]
// Node -> Node
// --> Header Hash ++ Key (Start) ++ Key (End) ++ Maximum Size
// --> FIN
// <-- [Boundary Node]
// <-- [Key ++ Value]
// <-- FIN
func (n *Node) RequestState(ctx context.Context, headerHash crypto.Hash, keyStart [31]byte, keyEnd [31]byte, maxSize uint32, peerKey ed25519.PublicKey) (store.TrieRangeResult, error) {
	// Acquire read lock to safely access the peer set
	n.peersLock.RLock()
	defer n.peersLock.RUnlock()

	// Find the peer with the specified Ed25519 public key
	if existingPeer := n.PeersSet.GetByEd25519Key(peerKey); existingPeer != nil {
		// Open a new stream of the StateRequest kind to the peer
		stream, err := existingPeer.ProtoConn.OpenStream(ctx, protocol.StreamKindStateRequest)
		if err != nil {
			return store.TrieRangeResult{}, fmt.Errorf("state request: open stream: %w", err)
		}

		// Ensure the stream is closed when the function returns
		defer stream.Close()

		// Use the StateRequester to perform the actual request
		// This sends the request message and processes the response
		result, err := n.stateReqester.RequestState(ctx, stream, headerHash, keyStart, keyEnd, maxSize)
		if err != nil {
			return store.TrieRangeResult{}, fmt.Errorf("state request: request state from peer: %w", err)
		}

		// Return the result containing boundary nodes and key-value pairs
		return result, nil
	}

	// Return an error if no peer was found with the specified key
	return store.TrieRangeResult{}, fmt.Errorf("state request: no peer available with the specified Ed25519 key")
}

// SubmitTicket implements the CE 131 Safrole ticket submission protocol.
// CE 131 Protocol Flow (Generating Validator -> Proxy Validator):
//  1. A validator generates a Safrole ticket for the current epoch
//  2. The ticket is sent to a deterministically-selected "proxy" validator
//  3. The proxy validator index is determined by: last 4 bytes of ticket's VRF output
//     as big-endian uint32, modulo number of validators
//  4. Proxy is selected from the NEXT epoch's validator list
//
// --> Epoch Index ++ Ticket (epoch that ticket will be used in)
// --> FIN
// <-- FIN
func (n *Node) SubmitTicket(ctx context.Context, ticket block.TicketProof, peerKey ed25519.PublicKey) error {
	return n.sendTicket(ctx, protocol.StreamKindSafroleTicketSubmit, ticket, peerKey)
}

// TODO: Timing of ticket distribution and actual execution of the protocol.
// CE 132 Protocol Requirements:
// - Proxy validator must send ticket to ALL current validators (broadcast)
// - Distribution should be evenly spaced over time to avoid network congestion
// - Should stop if ticket gets included in a finalized block
// - Timing: Start 3 minutes after connectivity changes, spread until halfway through lottery period
func (n *Node) DistributeTicketToAll(ctx context.Context, ticket block.TicketProof) error {
	n.peersLock.RLock()
	peers := n.PeersSet.GetAllPeers()
	n.peersLock.RUnlock()

	if len(peers) == 0 {
		return fmt.Errorf("no peers available for ticket distribution")
	}

	for _, peer := range peers {
		if peer.IsValidator() {
			if err := n.DistributeTicketToPeer(ctx, ticket, peer.Ed25519Key); err != nil {
				//log error and continue to the next peer
				log.Printf("failed to distribute ticket to validatorindex %d: %v", peer.ValidatorIndex, err)
			}
		}
	}

	return nil
}

// DistributeTicketToPeer implements the CE 132 Safrole ticket distribute protocol.
// --> Epoch Index ++ Ticket
// --> FIN
// <-- FIN
func (n *Node) DistributeTicketToPeer(ctx context.Context, ticket block.TicketProof, peerKey ed25519.PublicKey) error {
	return n.sendTicket(ctx, protocol.StreamKindSafroleTicketDist, ticket, peerKey)
}

// sendTicket is the common implementation for both CE 131 and CE 132 protocols.
// The protocols are identical on the wire - the difference is in their usage:
// - CE 131: Generating validator -> Proxy validator (1-to-1)
// - CE 132: Proxy validator -> All current validators (1-to-many broadcast)
//
// Protocol Details:
// - Both use the same message format: Epoch Index + Ticket data
// - Epoch Index identifies which epoch the ticket will be used for block production
// - Simple request-response: sender transmits data, receiver acknowledges with FIN
func (n *Node) sendTicket(ctx context.Context, streamKind protocol.StreamKind, ticket block.TicketProof, peerKey ed25519.PublicKey) error {
	var existingPeer *peer.Peer
	n.peersLock.RLock()
	existingPeer = n.PeersSet.GetByEd25519Key(peerKey)
	n.peersLock.RUnlock()

	if existingPeer == nil {
		return fmt.Errorf("no peers available to submit ticket")
	}

	stream, err := existingPeer.ProtoConn.OpenStream(ctx, streamKind)
	if err != nil {
		return fmt.Errorf("failed to open stream: %w", err)
	}
	defer stream.Close()

	if err := n.safroleTicketSubmiter.Submit(ctx, stream, ticket); err != nil {
		return fmt.Errorf("failed to submit ticket: %w", err)
	}
	return nil
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

func (n *Node) onBlockReceivedDistributeShards(ctx context.Context, block block.Block) {
	select {
	case <-ctx.Done():
		log.Printf("failed to get the shards for assurance: %s", ctx.Err())
	default:
		for _, guarantee := range block.Extrinsic.EG.Guarantees {
			if err := n.GetGuaranteedShardsAndStore(n.Context, guarantee); err != nil {
				log.Printf("failed get the shards and store: %s", err)
			}
		}
	}
}

// GetGuaranteedShardsAndStore requests the shards from the appropriate guarantors,
// if shard distribution request fails, will try again for the next guarantor, if unable to get shards from any guarantor will fail
func (n *Node) GetGuaranteedShardsAndStore(ctx context.Context, guarantee block.Guarantee) error {
	for _, credential := range guarantee.Credentials {
		peer := n.PeersSet.GetByValidatorIndex(credential.ValidatorIndex)
		if peer == nil {
			return fmt.Errorf("peer with validator index %d not found", credential.ValidatorIndex)
		}

		erasureRoot := guarantee.WorkReport.WorkPackageSpecification.ErasureRoot
		validatorIndex := n.ValidatorManager.Index

		bundleShard, segmentsShard, justification, err := n.ShardDistributionSend(ctx, peer.Ed25519Key, guarantee.WorkReport.CoreIndex, erasureRoot)
		if err != nil {
			log.Printf("Error getting shards from guarantor with index %d; trying again with other guarantor", credential.ValidatorIndex)
			continue
		}

		if err := n.AvailabilityStore.PutShardsAndJustification(erasureRoot, validatorIndex, bundleShard, segmentsShard, justification); err != nil {
			return fmt.Errorf("failed to store shards and justification: %w", err)
		}

		return nil
	}

	return fmt.Errorf("unable to get shards from guarantors")
}

// GetByAddress acquires the lock and return peer by address
// TODO: Temporary workaround for avoiding data race in e2e test. Should be removed after proper test setup is implemented.
func (n *Node) GetByAddress(addr string) *peer.Peer {
	n.peersLock.RLock()
	defer n.peersLock.RUnlock()

	return n.PeersSet.GetByAddress(addr)
}
