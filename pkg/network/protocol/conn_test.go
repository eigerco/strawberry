package protocol

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/eigerco/strawberry/pkg/network/mocks"
	"github.com/quic-go/quic-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// AddStreamForTesting allows adding a stream to a ProtocolConn for testing purposes.
// This function should only be used in tests.
func (pc *ProtocolConn) AddStreamForTesting(kind StreamKind, stream quic.Stream) {
	pc.mu.Lock()
	defer pc.mu.Unlock()
	pc.streams[kind] = stream
}

// GetStreamsForTesting returns a copy of the streams map for testing.
// This function should only be used in tests.
func (pc *ProtocolConn) GetStreamsForTesting() map[StreamKind]quic.Stream {
	pc.mu.RLock()
	defer pc.mu.RUnlock()

	result := make(map[StreamKind]quic.Stream, len(pc.streams))
	for k, v := range pc.streams {
		result[k] = v
	}
	return result
}
func TestNewProtocolConn(t *testing.T) {
	mockTConn := mocks.NewMockTransportConn()
	registry := NewJAMNPRegistry()

	// Execute
	conn := NewProtocolConn(mockTConn, registry)

	assert.NotNil(t, conn)
	assert.Same(t, mockTConn, conn.TConn)
	assert.Same(t, registry, conn.Registry)
}

func TestProtocolConn_OpenStream(t *testing.T) {
	mockTConn := mocks.NewMockTransportConn()
	registry := NewJAMNPRegistry()
	mockStream := mocks.NewMockQuicStream()

	conn := NewProtocolConn(mockTConn, registry)

	// Configure mocks
	ctx := context.Background()
	mockTConn.On("OpenStream", ctx).Return(mockStream, nil)
	mockStream.On("Write", []byte{byte(StreamKindBlockRequest)}).Return(1, nil)

	// Execute
	stream, err := conn.OpenStream(ctx, StreamKindBlockRequest)

	require.NoError(t, err)
	assert.Same(t, mockStream, stream)
	mockTConn.AssertExpectations(t)
	mockStream.AssertExpectations(t)
}

func TestProtocolConn_OpenStream_Error(t *testing.T) {
	mockTConn := mocks.NewMockTransportConn()
	registry := NewJAMNPRegistry()

	conn := NewProtocolConn(mockTConn, registry)

	// Configure mocks
	ctx := context.Background()
	expectedErr := errors.New("open stream error")
	mockTConn.On("OpenStream", ctx).Return(nil, expectedErr)

	// Execute
	stream, err := conn.OpenStream(ctx, StreamKindBlockRequest)

	assert.Nil(t, stream)
	assert.ErrorIs(t, err, expectedErr)
	mockTConn.AssertExpectations(t)
}

func TestProtocolConn_OpenStream_WriteError(t *testing.T) {
	mockTConn := mocks.NewMockTransportConn()
	registry := NewJAMNPRegistry()
	mockStream := mocks.NewMockQuicStream()

	conn := NewProtocolConn(mockTConn, registry)

	// Configure mocks
	ctx := context.Background()
	mockTConn.On("OpenStream", ctx).Return(mockStream, nil)
	writeErr := errors.New("write error")
	mockStream.On("Write", []byte{byte(StreamKindBlockRequest)}).Return(0, writeErr)
	mockStream.On("Close").Return(nil)

	// Execute
	stream, err := conn.OpenStream(ctx, StreamKindBlockRequest)

	assert.Nil(t, stream)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to write stream kind")
	mockTConn.AssertExpectations(t)
	mockStream.AssertExpectations(t)
}

func TestProtocolConn_AcceptStream(t *testing.T) {
	mockTConn := mocks.NewMockTransportConn()
	registry := NewJAMNPRegistry()
	mockStream := mocks.NewMockQuicStream()
	mockHandler := mocks.NewMockStreamHandler()

	conn := NewProtocolConn(mockTConn, registry)

	// Register a handler for the test stream kind
	streamKind := StreamKindBlockRequest
	registry.RegisterHandler(streamKind, mockHandler)

	// Configure mocks
	mockTConn.On("AcceptStream").Return(mockStream, nil)
	mockTConn.On("Context").Return(mockTConn.Context())
	mockTConn.On("PeerKey").Return(mockTConn.PeerKey())

	// Setup mockStream to return the stream kind when Read is called
	mockStream.On("Read", mock.Anything).Run(func(args mock.Arguments) {
		b := args.Get(0).([]byte)
		b[0] = byte(streamKind)
	}).Return(1, nil)

	// Setup handler expectations
	mockHandler.On("HandleStream", mock.Anything, mockStream, mockTConn.PeerKey()).Return(nil)

	// Execute
	err := conn.AcceptStream()

	// Give time for the goroutine to execute
	time.Sleep(10 * time.Millisecond)

	require.NoError(t, err)
	mockTConn.AssertExpectations(t)
	mockStream.AssertExpectations(t)
	mockHandler.AssertExpectations(t)
}

func TestProtocolConn_AcceptStream_TransportError(t *testing.T) {
	mockTConn := mocks.NewMockTransportConn()
	registry := NewJAMNPRegistry()

	conn := NewProtocolConn(mockTConn, registry)

	// Configure mocks
	expectedErr := errors.New("accept error")
	mockTConn.On("AcceptStream").Return(nil, expectedErr)

	// Execute
	err := conn.AcceptStream()

	assert.ErrorIs(t, err, expectedErr)
	mockTConn.AssertExpectations(t)
}

func TestProtocolConn_AcceptStream_ReadError(t *testing.T) {
	mockTConn := mocks.NewMockTransportConn()
	registry := NewJAMNPRegistry()
	mockStream := mocks.NewMockQuicStream()

	conn := NewProtocolConn(mockTConn, registry)

	// Configure mocks
	mockTConn.On("AcceptStream").Return(mockStream, nil)
	readErr := errors.New("read error")
	mockStream.On("Read", mock.Anything).Return(0, readErr)
	mockStream.On("Close").Return(nil)

	// Execute
	err := conn.AcceptStream()

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to read stream kind")
	mockTConn.AssertExpectations(t)
	mockStream.AssertExpectations(t)
}

func TestProtocolConn_AcceptStream_NoHandler(t *testing.T) {
	mockTConn := mocks.NewMockTransportConn()
	registry := NewJAMNPRegistry()
	mockStream := mocks.NewMockQuicStream()

	conn := NewProtocolConn(mockTConn, registry)

	// Set up stream to return a kind with no registered handler
	streamKind := StreamKindBlockRequest // No handler registered
	mockTConn.On("AcceptStream").Return(mockStream, nil)
	mockStream.On("Read", mock.Anything).Run(func(args mock.Arguments) {
		b := args.Get(0).([]byte)
		b[0] = byte(streamKind)
	}).Return(1, nil)
	mockStream.On("Close").Return(nil)

	// Execute
	err := conn.AcceptStream()

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no handler for kind")
	mockTConn.AssertExpectations(t)
	mockStream.AssertExpectations(t)
}

func TestProtocolConn_Close(t *testing.T) {
	mockTConn := mocks.NewMockTransportConn()
	registry := NewJAMNPRegistry()
	mockStream1 := mocks.NewMockQuicStream()
	mockStream2 := mocks.NewMockQuicStream()

	conn := NewProtocolConn(mockTConn, registry)

	// Add test streams to the connection
	conn.AddStreamForTesting(StreamKindBlockAnnouncement, mockStream1)
	conn.AddStreamForTesting(StreamKindBlockRequest, mockStream2)

	// Configure mocks
	mockStream1.On("Close").Return(nil)
	mockStream2.On("Close").Return(nil)
	mockTConn.On("Close").Return(nil)

	// Execute
	err := conn.Close()

	require.NoError(t, err)
	assert.Empty(t, conn.GetStreamsForTesting())
	mockStream1.AssertExpectations(t)
	mockStream2.AssertExpectations(t)
	mockTConn.AssertExpectations(t)
}

func TestProtocolConn_Close_Error(t *testing.T) {
	mockTConn := mocks.NewMockTransportConn()
	registry := NewJAMNPRegistry()

	conn := NewProtocolConn(mockTConn, registry)

	expectedErr := errors.New("close error")
	mockTConn.On("Close").Return(expectedErr)

	// Execute
	err := conn.Close()

	assert.ErrorIs(t, err, expectedErr)
	mockTConn.AssertExpectations(t)
}

func TestWriteWithContext(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		mockStream := mocks.NewMockQuicStream()
		ctx := context.Background()
		data := []byte("test data")

		mockStream.On("Write", data).Return(len(data), nil)

		// Execute
		err := writeWithContext(ctx, mockStream, data)

		assert.NoError(t, err)
		mockStream.AssertExpectations(t)
	})

	// Test write error
	t.Run("WriteError", func(t *testing.T) {
		mockStream := mocks.NewMockQuicStream()
		ctx := context.Background()
		data := []byte("test data")
		expectedErr := errors.New("write error")

		mockStream.On("Write", data).Return(0, expectedErr)

		// Execute
		err := writeWithContext(ctx, mockStream, data)

		assert.ErrorIs(t, err, expectedErr)
		mockStream.AssertExpectations(t)
	})

	// Test context cancellation
	t.Run("ContextCancelled", func(t *testing.T) {
		// Create a new mock for each subtest
		mockStream := mocks.NewMockQuicStream()
		ctx, cancel := context.WithCancel(context.Background())
		data := []byte("test data")
		mockStream.On("Write", mock.Anything).Maybe().Return(0, nil)

		cancel()

		// Execute
		err := writeWithContext(ctx, mockStream, data)

		assert.ErrorIs(t, err, context.Canceled)
	})
}
