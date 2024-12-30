package protocol

import (
	"context"
	"fmt"
	"sync"

	"github.com/eigerco/strawberry/pkg/network/transport"
	"github.com/quic-go/quic-go"
)

// ProtocolConn wraps a transport connection with protocol-specific functionality.
// It manages stream multiplexing, handles stream kinds, and maintains unique persistent streams.
type ProtocolConn struct {
	tConn     *transport.Conn
	mu        sync.RWMutex
	upStreams map[StreamKind]quic.Stream
	registry  *JAMNPRegistry
}

// NewProtocolConn creates a new protocol-level connection.
// It initializes stream management and associates the connection with a handler registry.
func NewProtocolConn(tConn *transport.Conn, registry *JAMNPRegistry) *ProtocolConn {
	return &ProtocolConn{
		tConn:     tConn,
		upStreams: make(map[StreamKind]quic.Stream),
		registry:  registry,
	}
}

// OpenStream opens a new stream of the given kind using the provided context.
// It writes the stream kind as the first byte and returns the established stream.
// Returns an error if stream creation or initial write fails.
func (pc *ProtocolConn) OpenStream(ctx context.Context, kind StreamKind) (quic.Stream, error) {
	// Use the passed context for opening the stream
	stream, err := pc.tConn.OpenStream(ctx)
	if err != nil {
		return nil, err
	}

	// Write stream kind
	if err := writeWithContext(ctx, stream, []byte{byte(kind)}); err != nil {
		stream.Close()
		return nil, fmt.Errorf("failed to write stream kind: %w", err)
	}

	return stream, nil
}

// TODO: to be used in the future
// handleUPStream manages unique persistent streams
// func (pc *ProtocolConn) handleUPStream(kind StreamKind, stream quic.Stream) (quic.Stream, error) {
// 	pc.mu.Lock()
// 	defer pc.mu.Unlock()

// 	if existing, exists := pc.upStreams[kind]; exists {
// 		// Keep stream with higher ID
// 		if existing.StreamID() > stream.StreamID() {
// 			stream.Close()
// 			return existing, nil
// 		} else {
// 			existing.Close()
// 			pc.upStreams[kind] = stream
// 		}
// 	} else {
// 		pc.upStreams[kind] = stream
// 	}
// 	return stream, nil
// }

// AcceptStream accepts and handles an incoming stream.
// It reads the stream kind byte, looks up the appropriate handler,
// and starts a goroutine to handle the stream.
// Returns an error if accepting the stream or reading the kind fails.
func (pc *ProtocolConn) AcceptStream() error {
	stream, err := pc.tConn.AcceptStream()
	if err != nil {
		return err
	}

	// Read stream kind
	kind := make([]byte, 1)
	if _, err := stream.Read(kind); err != nil {
		stream.Close()
		return fmt.Errorf("failed to read stream kind: %w", err)
	}

	// Get handler for this stream kind
	handler, err := pc.registry.GetHandler(kind[0])
	if err != nil {
		stream.Close()
		return err
	}

	// Handle the stream
	go func() {
		if err := handler.HandleStream(pc.tConn.Context(), stream); err != nil {
			fmt.Printf("stream handler error: %v\n", err)
		}
	}()

	return nil
}

// writeWithContext writes bytes to a stream with context cancellation support.
// It allows the write operation to be cancelled via the context.
// Returns an error if the write fails or the context is cancelled.
func writeWithContext(ctx context.Context, stream quic.Stream, p []byte) error {
	done := make(chan error, 1)

	go func() {
		_, err := stream.Write(p)
		done <- err
	}()

	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Close closes the protocol connection and all associated UP streams.
// It ensures all resources are properly cleaned up.
// Returns an error if closing the underlying transport connection fails.
func (pc *ProtocolConn) Close() error {
	pc.mu.Lock()
	defer pc.mu.Unlock()

	// Close all UP streams
	for _, stream := range pc.upStreams {
		if err := stream.Close(); err != nil {
			fmt.Printf("Error closing stream: %v\n", err)
		}
	}
	pc.upStreams = make(map[StreamKind]quic.Stream)

	return pc.tConn.Close()
}
