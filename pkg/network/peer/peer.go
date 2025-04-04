package peer

import (
	"context"
	"crypto/ed25519"
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
