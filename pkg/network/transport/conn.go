package transport

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"github.com/quic-go/quic-go"
	"time"
)

const StreamTimeout = 5 * time.Second

// Conn represents a basic QUIC connection
type Conn struct {
	qConn     quic.Connection
	transport *Transport
	peerKey   ed25519.PublicKey
	ctx       context.Context
	cancel    context.CancelFunc
}

// newConn creates a new connection
func newConn(qConn quic.Connection, transport *Transport) *Conn {
	ctx, cancel := context.WithCancel(transport.ctx)

	conn := &Conn{
		qConn:     qConn,
		transport: transport,
		ctx:       ctx,
		cancel:    cancel,
	}

	// Ensure cleanup when connection ends
	go func() {
		<-ctx.Done()
		conn.cleanup()
	}()

	return conn
}

func (c *Conn) cleanup() {
	if c.peerKey != nil {
		c.transport.cleanup(c.peerKey)
	}
}

// OpenStream opens a raw QUIC stream
func (c *Conn) OpenStream(ctx context.Context) (quic.Stream, error) {
	stream, err := c.qConn.OpenStreamSync(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to open QUIC stream: %w", err)
	}

	return stream, nil
}

// AcceptStream accepts a raw incoming stream
func (c *Conn) AcceptStream() (quic.Stream, error) {
	stream, err := c.qConn.AcceptStream(c.ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to accept QUIC stream: %w", err)
	}
	return stream, nil
}

// PeerKey returns the peer's public key
func (c *Conn) PeerKey() ed25519.PublicKey {
	return c.peerKey
}

// Close closes the connection
func (c *Conn) Close() error {
	c.cancel()
	return c.qConn.CloseWithError(0, "")
}

// Context returns the connection's context
func (c *Conn) Context() context.Context {
	return c.ctx
}
