package peer

import (
	"context"
	"crypto/ed25519"
	"fmt"

	"github.com/eigerco/strawberry/pkg/network/handlers"
	"github.com/eigerco/strawberry/pkg/network/protocol"
	"github.com/eigerco/strawberry/pkg/network/transport"
)

// Peer represents a remote peer and provides high-level protocol operations.
// It wraps the underlying transport and protocol connections with a simpler interface.
type Peer struct {
	// conn is the underlying transport connection
	conn *transport.Conn
	// protoConn handles protocol-specific operations
	protoConn *protocol.ProtocolConn
	// pubKey uniquely identifies the remote peer
	pubKey ed25519.PublicKey
}

// NewPeer creates a new peer instance from an established transport connection.
// It wraps the connection with protocol-specific functionality using the provided manager.
// Parameters:
//   - conn: The underlying transport connection
//   - pubKey: The peer's Ed25519 public key
//   - protoManager: The protocol manager for handling streams
func NewPeer(conn *transport.Conn, pubKey ed25519.PublicKey, protoManager *protocol.Manager) *Peer {
	return &Peer{
		conn:      conn,
		protoConn: protoManager.WrapConnection(conn),
		pubKey:    pubKey,
	}
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
	stream, err := p.protoConn.OpenStream(ctx, protocol.StreamKindBlockRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to open stream: %w", err)
	}
	defer stream.Close()

	requester := &handlers.BlockRequester{}
	return requester.RequestBlocks(ctx, stream, headerHash, ascending)
}
