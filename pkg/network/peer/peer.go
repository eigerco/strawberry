package peer

import (
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"fmt"
	"net"
	"sync"

	"github.com/eigerco/strawberry/internal/block"
	"github.com/eigerco/strawberry/internal/chain"
	"github.com/eigerco/strawberry/pkg/network/handlers"
	"github.com/eigerco/strawberry/pkg/network/protocol"
)

type PeerAddress struct {
	IP   net.IP
	Port uint16
}

// Peer represents a remote peer and provides high-level protocol operations.
// It wraps the underlying transport and protocol connections with a simpler interface.
type Peer struct {
	// ProtoConn handles protocol-specific operations
	ProtoConn  *protocol.ProtocolConn
	Address    PeerAddress
	mu         sync.RWMutex
	ctx        context.Context
	cancel     context.CancelFunc
	baHandler  *handlers.BlockAnnouncementHandler
	Ed25519Key ed25519.PublicKey
	// Optional validator index if this peer is a validator
	ValidatorIndex *uint16
}

// NewPeer creates a new peer instance from an established transport connection.
func NewPeer(pConn *protocol.ProtocolConn) *Peer {
	ctx, cancel := context.WithCancel(pConn.TConn.Context())
	remoteAddr := pConn.TConn.QConn.RemoteAddr().String()
	addres := PeerAddress{
		IP:   net.ParseIP(remoteAddr),
		Port: uint16(pConn.TConn.QConn.RemoteAddr().(*net.UDPAddr).Port),
	}
	p := &Peer{
		ProtoConn:  pConn,
		ctx:        ctx,
		cancel:     cancel,
		Ed25519Key: pConn.TConn.PeerKey(),
		Address:    addres,
	}
	return p
}

func NewPeerAddressFromMetadata(metadata []byte) PeerAddress {
	if len(metadata) < 18 {
		panic("metadata must be at least 18 bytes")
	}

	return PeerAddress{
		IP:   net.IP(metadata[:16]),
		Port: binary.LittleEndian.Uint16(metadata[16:18]),
	}
}

func (pa PeerAddress) String() string {
	return net.JoinHostPort(pa.IP.String(), fmt.Sprintf("%d", pa.Port))
}

// RequestBlocks requests a sequence of blocks from the peer.
// Opens a block request stream and handles the protocol interaction.
// Parameters:
//   - ctx: Context for cancellation
//   - headerHash: Hash of the header to start from
//   - ascending: If true, gets blocks after header, if false, gets blocks before
//
// Returns:
//   - The requested blocks data or an error if the request fails
func (p *Peer) RequestBlocks(ctx context.Context, headerHash [32]byte, ascending bool) ([]byte, error) {
	stream, err := p.ProtoConn.OpenStream(ctx, protocol.StreamKindBlockRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to open stream: %w", err)
	}
	defer stream.Close()

	requester := &handlers.BlockRequester{}
	return requester.RequestBlocks(ctx, stream, headerHash, ascending)
}

func (p *Peer) AnnounceBlock(bs *chain.BlockService, ctx context.Context, header *block.Header) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	// If baHandler is nil, we need to get it from the registry
	if p.baHandler == nil {
		handler, err := p.ProtoConn.Registry.GetHandler(byte(protocol.StreamKindBlockAnnouncement))
		if err != nil {
			return fmt.Errorf("failed to get announcement handler: %w", err)
		}

		// Type assert to get the BlockAnnouncementHandler
		blockHandler, ok := handler.(*handlers.BlockAnnouncementHandler)
		if !ok {
			return fmt.Errorf("invalid handler type for block announcements")
		}
		p.baHandler = blockHandler
	}

	// Check if we already have an announcer for this peer
	announcer, ok := p.baHandler.Announcers[string(p.ProtoConn.TConn.PeerKey())]
	if ok {
		return announcer.SendAnnouncement(header)
	}

	// First time: set up the announcer
	stream, err := p.ProtoConn.OpenStream(ctx, protocol.StreamKindBlockAnnouncement)
	if err != nil {
		return fmt.Errorf("failed to open stream: %w", err)
	}

	// Create new announcement handler
	announcer = p.baHandler.NewBlockAnnouncer(bs, p.ProtoConn.TConn.Context(), stream, p.ProtoConn.TConn.PeerKey())

	// Start the handler (this will handle handshake)
	errCh := make(chan error, 1)
	go func() {
		errCh <- announcer.Start()
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

	// Now that handshake is complete, send the announcement
	return announcer.SendAnnouncement(header)
}
