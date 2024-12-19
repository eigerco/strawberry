package peer

import (
	"context"
	"crypto/ed25519"
	"fmt"

	"github.com/eigerco/strawberry/pkg/network/handlers"
	"github.com/eigerco/strawberry/pkg/network/protocol"
	"github.com/eigerco/strawberry/pkg/network/transport"
)

type Peer struct {
	// Core connection
	conn      *transport.Conn
	protoConn *protocol.ProtocolConn
	// Peer identity
	pubKey ed25519.PublicKey
}

func NewPeer(conn *transport.Conn, pubKey ed25519.PublicKey, protoManager *protocol.Manager) *Peer {
	return &Peer{
		conn:      conn,
		protoConn: protoManager.WrapConnection(conn),
		pubKey:    pubKey,
	}
}

// RequestBlocks requests blocks from the peer
func (p *Peer) RequestBlocks(ctx context.Context, headerHash [32]byte, ascending bool) ([]byte, error) {
	stream, err := p.protoConn.OpenStream(ctx, protocol.StreamKindBlockRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to open stream: %w", err)
	}
	defer stream.Close()

	requester := &handlers.BlockRequester{}
	return requester.RequestBlocks(ctx, stream, headerHash, ascending)
}
