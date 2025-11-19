package peer

import (
	"context"

	"github.com/eigerco/strawberry/internal/crypto/ed25519"

	"fmt"
	"net"
	"net/netip"

	"github.com/eigerco/strawberry/internal/block"
	"github.com/eigerco/strawberry/pkg/network/protocol"
)

type BlockAnnouncer interface {
	// Add the rest of the functions when needed
	SendAnnouncement(header *block.Header) error
	Start() error
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

	if peer.IsValidator() {
		ps.byValidatorIndex[*peer.ValidatorIndex] = peer
	}
}

// RemovePeer removes a peer from all lookup maps in the PeerSet.
func (ps *PeerSet) RemovePeer(peer *Peer) {
	delete(ps.byEd25519Key, string(peer.Ed25519Key))
	delete(ps.byAddress, peer.Address.String())

	if peer.IsValidator() {
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

// GetAllPeers returns all peers currently in the peer set
func (ps *PeerSet) GetAllPeers() []*Peer {
	peers := make([]*Peer, 0, len(ps.byEd25519Key))
	for _, peer := range ps.byEd25519Key {
		peers = append(peers, peer)
	}
	return peers
}

// Peer represents a remote peer and provides high-level protocol operations.
// It wraps the underlying transport and protocol connections with a simpler interface.
type Peer struct {
	// ProtoConn handles protocol-specific operations
	ProtoConn  *protocol.ProtocolConn
	Address    *net.UDPAddr
	ctx        context.Context
	cancel     context.CancelFunc
	Ed25519Key ed25519.PublicKey
	BAnnouncer BlockAnnouncer
	// Optional validator index if this peer is a validator
	ValidatorIndex *uint16
}

// NewPeer creates a new peer instance from an established transport connection.
func NewPeer(pConn *protocol.ProtocolConn) *Peer {
	ctx, cancel := context.WithCancel(pConn.TConn.Context())
	remoteAddr, ok := pConn.TConn.QConn().RemoteAddr().(*net.UDPAddr)
	if !ok {
		cancel()
		return nil
	}
	p := &Peer{
		ProtoConn:  pConn,
		ctx:        ctx,
		cancel:     cancel,
		Ed25519Key: pConn.TConn.PeerKey(),
		Address:    remoteAddr,
	}
	return p
}

// IsValidator returns true if the peer is a validator, false otherwise
// A validator peer should have a non-nil ValidatorIndex field.
func (p *Peer) IsValidator() bool {
	return p != nil && p.ValidatorIndex != nil
}

// The first 18 bytes of validator metadata, with the first 16 bytes being the IPv6 address
// and the latter 2 being a little endian representation of the port.
func NewPeerAddressFromMetadata(metadata []byte) (*net.UDPAddr, error) {
	if len(metadata) < 18 {
		return nil, fmt.Errorf("metadata too short: got %d bytes, want at least 18", len(metadata))
	}

	var address netip.AddrPort
	if err := address.UnmarshalBinary(metadata[:18]); err != nil {
		return nil, fmt.Errorf("failed to unmarshal address: %w", err)
	}

	return net.UDPAddrFromAddrPort(address), nil
}

// MergeValidators returns a deduplicated set of validator peers from slices a and b,
// including only peers that are validators (ValidatorIndex != nil)
// Deduplication is performed based on Ed25519 public keys
func MergeValidators(a, b []*Peer) []*Peer {
	exists := make(map[string]struct{})
	var merged []*Peer

	// Include only valid peers from `a`
	for _, p := range a {
		if !p.IsValidator() {
			continue
		}
		key := string(p.Ed25519Key)
		if _, seen := exists[key]; !seen {
			exists[key] = struct{}{}
			merged = append(merged, p)
		}
	}

	// Include only valid, non-duplicate peers from `b`
	for _, p := range b {
		if !p.IsValidator() {
			continue
		}
		key := string(p.Ed25519Key)
		if _, seen := exists[key]; !seen {
			exists[key] = struct{}{}
			merged = append(merged, p)
		}
	}

	return merged
}
