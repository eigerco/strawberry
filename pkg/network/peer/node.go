package peer

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/eigerco/strawberry/internal/block"
	"github.com/eigerco/strawberry/internal/chain"
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/crypto/bandersnatch"
	"github.com/eigerco/strawberry/internal/jamtime"
	"github.com/eigerco/strawberry/internal/validator"
	"github.com/eigerco/strawberry/pkg/network"
	"github.com/eigerco/strawberry/pkg/network/cert"
	"github.com/eigerco/strawberry/pkg/network/handlers"
	"github.com/eigerco/strawberry/pkg/network/protocol"
	"github.com/eigerco/strawberry/pkg/network/transport"
)

// PeerSet manages a collection of peers with efficient lookups
type PeerSet struct {
	// Map from Ed25519 public key to peer
	byEd25519Key map[string]*Peer

	// Map from string representation of address to peer
	byAddress map[string]*Peer

	// Map from validator index to peer (only for validator peers)
	byValidatorIndex map[uint16]*Peer
}

func NewPeerSet() *PeerSet {
	return &PeerSet{
		byEd25519Key:     make(map[string]*Peer),
		byAddress:        make(map[string]*Peer),
		byValidatorIndex: make(map[uint16]*Peer),
	}
}
func (ps *PeerSet) AddPeer(peer *Peer) {
	ps.byEd25519Key[string(peer.Ed25519Key)] = peer
	ps.byAddress[peer.Address.String()] = peer

	if peer.ValidatorIndex != nil {
		ps.byValidatorIndex[*peer.ValidatorIndex] = peer
	}
}

func (ps *PeerSet) RemovePeer(peer *Peer) {
	delete(ps.byEd25519Key, string(peer.Ed25519Key))
	delete(ps.byAddress, peer.Address.String())

	if peer.ValidatorIndex != nil {
		delete(ps.byValidatorIndex, *peer.ValidatorIndex)
	}
}

// GetByEd25519Key looks up a peer by Ed25519 public key
func (ps *PeerSet) GetByEd25519Key(key ed25519.PublicKey) *Peer {
	return ps.byEd25519Key[string(key)]
}

// GetByAddress looks up a peer by network address
func (ps *PeerSet) GetByAddress(addr string) *Peer {
	return ps.byAddress[addr]
}

// GetByValidatorIndex looks up a peer by validator index
func (ps *PeerSet) GetByValidatorIndex(index uint16) *Peer {
	return ps.byValidatorIndex[index]
}

type Node struct {
	ValidatorManager *validator.ValidatorManager
	Context          context.Context
	Cancel           context.CancelFunc
	blockService     *chain.BlockService
	transport        *transport.Transport
	protocolManager  *protocol.Manager
	peersLock        sync.RWMutex
	peersSet         *PeerSet
}

func NewNode(nodeCtx context.Context, listenAddr string, keys validator.ValidatorKeys, state validator.ValidatorState, validatorIdx uint16) (*Node, error) {
	nodeCtx, cancel := context.WithCancel(nodeCtx)
	node := &Node{
		peersSet: NewPeerSet(),
		Context:  nodeCtx,
		Cancel:   cancel,
	}
	node.ValidatorManager = validator.NewValidatorManager(keys, state, validatorIdx)

	// Create block service
	bs, err := chain.NewBlockService()
	if err != nil {
		return nil, fmt.Errorf("failed to create block service: %w", err)
	}

	// Set up genesis block
	h0 := block.Header{
		ParentHash:    crypto.Hash{},
		TimeSlotIndex: jamtime.Timeslot(0),
	}
	b0 := block.Block{
		Header: h0,
	}
	err = bs.Store.PutBlock(b0)
	if err != nil {
		return nil, fmt.Errorf("failed to store genesis block: %w", err)
	}

	// Create certificate
	certGen := cert.NewGenerator(cert.Config{
		PublicKey:          keys.EdPub,
		PrivateKey:         keys.EdPrv,
		CertValidityPeriod: 24 * time.Hour,
	})
	tlsCert, err := certGen.GenerateCertificate()
	if err != nil {
		return nil, fmt.Errorf("failed to generate certificate: %w", err)
	}

	// Create protocol manager
	protoConfig := protocol.Config{
		ChainHash:       "12345678",
		IsBuilder:       true,
		MaxBuilderSlots: 20,
	}
	protoManager, err := protocol.NewManager(protoConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create protocol manager: %w", err)
	}
	// Register handlers
	protoManager.Registry.RegisterHandler(protocol.StreamKindBlockRequest, handlers.NewBlockRequestHandler(bs))
	protoManager.Registry.RegisterHandler(protocol.StreamKindBlockAnnouncement, handlers.NewBlockAnnouncementHandler(bs, node))

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
	node.blockService = bs
	node.transport = tr
	node.protocolManager = protoManager
	return node, nil
}
func (n *Node) ValidateConnection(tlsState tls.ConnectionState) error {
	return n.protocolManager.ValidateConnection(tlsState)
}
func (n *Node) GetProtocols() []string {
	return n.protocolManager.GetProtocols()
}
func (n *Node) OnConnection(conn *transport.Conn) {
	n.peersLock.Lock()
	defer n.peersLock.Unlock()
	// If peer already exists, close existing connection and replace with new one
	if existingPeer := n.peersSet.GetByEd25519Key(conn.PeerKey()); existingPeer != nil {
		// Close existing connection
		if err := existingPeer.ProtoConn.Close(); err != nil {
			log.Printf("Failed to close existing peer connection: %v", err)
		}
		n.peersSet.RemovePeer(existingPeer)
	}

	pConn := n.protocolManager.OnConnection(conn)
	// Create new peer
	peer := NewPeer(pConn)

	// If it's a validator peer, add to validator manager
	if index, found := n.ValidatorManager.GridMapper.FindValidatorIndex(peer.Ed25519Key); found {
		peer.ValidatorIndex = &index
	}

	// Add to peer set
	n.peersSet.AddPeer(peer)
	log.Printf("Peer connected: %x", conn.PeerKey())
}

func (n *Node) Start() error {
	if err := n.transport.Start(); err != nil {
		return fmt.Errorf("failed to start transport: %w", err)
	}
	return nil
}

// blockTillNewTimeslot blocks until the next timeslot
func blockTillNewTimeslot() {
	currentSlot := jamtime.CurrentTimeslot()
	for {
		if currentSlot != jamtime.CurrentTimeslot() {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// TODO - Implement block production
// RunBlockProduction is a placeholder function for block production
func (n *Node) RunBlockProduction(fallbackKeys crypto.EpochKeys) {
	for {
		fmt.Printf("n.peers: %v\n", len(n.peersSet.byEd25519Key))
		blockTillNewTimeslot()
		currentSlot := jamtime.CurrentTimeslot()
		slotInEpoch := currentSlot.TimeslotInEpoch()
		slotKey := fallbackKeys[slotInEpoch]
		if n.ValidatorManager.IsSlotLeader(fallbackKeys) {
			// Create and sign new block
			header, err := createHeader(n.blockService, n.ValidatorManager.Index)
			if err != nil {
				log.Printf("Failed to create header: %v", err)
				continue
			}
			block := block.Block{
				Header: *header,
			}
			// Sign the block
			blockData, err := header.Bytes()
			if err != nil {
				log.Printf("Failed to serialize header: %v", err)
				continue
			}

			sig, err := bandersnatch.Sign(n.ValidatorManager.Keys.BanderPrv, blockData, []byte(""))
			if err != nil {
				log.Printf("Failed to sign header: %v", err)
				continue
			}

			// Verify signature
			valid, _ := bandersnatch.Verify(slotKey, blockData, []byte(""), sig)
			if !valid {
				log.Printf("Failed to verify own signature")
				continue
			}

			// Store the block first
			err = n.blockService.HandleNewHeader(header)
			if err != nil {
				log.Printf("Failed to handle new header: %v", err)
				continue
			}

			hash, err := header.Hash()
			if err != nil {
				log.Printf("Failed to hash header: %v", err)
				continue
			}

			err = n.blockService.Store.PutBlock(block)
			if err != nil {
				log.Printf("Failed to store block: %v", err)
				continue
			}
			network.LogBlockEvent(time.Now(), "producing", hash, currentSlot.ToEpoch(), currentSlot)
			for _, peer := range n.peersSet.byEd25519Key {
				if peer == nil {
					continue
				}
				announceCtx, cancel := context.WithTimeout(peer.ProtoConn.TConn.Context(), 10*time.Second)
				err = peer.AnnounceBlock(n.blockService, announceCtx, header)
				if err != nil {
					peerKey := string(peer.ProtoConn.TConn.PeerKey())
					log.Printf("Failed to announce block to peer %s: %v", peerKey, err)
				}
				cancel()
			}
			network.LogBlockEvent(time.Now(), "announcing", hash, currentSlot.ToEpoch(), currentSlot)
		}
	}
}

func (n *Node) ConnectToPeer(addr PeerAddress) error {
	// Check if peer already exists before attempting connection
	n.peersLock.RLock()
	if n.peersSet.GetByAddress(addr.String()) != nil {
		n.peersLock.RUnlock()
		return fmt.Errorf("peer already exists")
	}
	n.peersLock.RUnlock()
	// Establish connection
	if err := n.transport.Connect(addr.String()); err != nil {
		return fmt.Errorf("failed to connect to peer: %w", err)
	}
	return nil
}

func (n *Node) ConnectToNeighbours() error {
	neighbors, err := n.ValidatorManager.GetNeighbors()
	if err != nil {
		return fmt.Errorf("failed to get neighbors: %w", err)
	}
	for _, neighbor := range neighbors {
		address := NewPeerAddressFromMetadata(neighbor.Metadata[:])
		if err := n.ConnectToPeer(address); err != nil {
			return fmt.Errorf("failed to connect to neighbor: %w", err)
		}
	}
	return nil
}

// RequestBlock requests a block with the given hash from peers
func (n *Node) RequestBlock(ctx context.Context, hash crypto.Hash, ascending bool, peerKey ed25519.PublicKey) ([]byte, error) {
	n.peersLock.RLock()
	defer n.peersLock.RUnlock()

	if existingPeer := n.peersSet.GetByEd25519Key(peerKey); existingPeer != nil {
		// Create new block requester
		requester := &handlers.BlockRequester{}
		stream, err := existingPeer.ProtoConn.OpenStream(ctx, protocol.StreamKindBlockRequest)
		if err != nil {
			return nil, fmt.Errorf("failed to open stream: %w", err)
		}

		defer stream.Close()
		blockData, err := requester.RequestBlocks(ctx, stream, hash, ascending)
		if err != nil {
			return nil, fmt.Errorf("failed to request block from peer: %w", err)
		}
		return blockData, nil
	}
	return nil, fmt.Errorf("no peers available to request block from")
}

func (n *Node) Stop() error {
	n.Cancel()
	return n.transport.Stop()
}

// creteHeader creates a mock header for the next block
func createHeader(bs *chain.BlockService, index uint16) (*block.Header, error) {
	// Find the latest header we have
	var latestHeader block.Header
	_, err := bs.Store.FindHeader(func(h block.Header) bool {
		if h.TimeSlotIndex > latestHeader.TimeSlotIndex {
			latestHeader = h
		}
		return false // continue searching to find the highest slot
	})
	if err != nil {
		return &latestHeader, fmt.Errorf("failed to find latest header: %w", err)
	}
	hash, err := latestHeader.Hash()
	if err != nil {
		return &latestHeader, fmt.Errorf("failed to hash earliest block: %w", err)
	}
	newHeader := block.Header{
		ParentHash:       hash,
		TimeSlotIndex:    jamtime.CurrentTimeslot(),
		BlockAuthorIndex: index,
	}
	return &newHeader, nil
}
