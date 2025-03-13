package transport

import (
	"context"
	"crypto/ed25519"
	"errors"
	"testing"
	"time"

	"github.com/eigerco/strawberry/pkg/network/mocks"
	"github.com/eigerco/strawberry/pkg/network/mocks/quicconn"
	"github.com/quic-go/quic-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestNewConn(t *testing.T) {
	mockQConn := mocks.NewMockQuicConnection()
	mockQConn.On("Context").Return(context.Background())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	transport := &Transport{
		ctx:    ctx,
		cancel: cancel,
	}

	// Execute
	conn := newConn(mockQConn, transport)

	assert.NotNil(t, conn)
	assert.Equal(t, mockQConn, conn.QConn())
	assert.Equal(t, transport, conn.transport)
	assert.NotNil(t, conn.ctx)
	assert.NotNil(t, conn.cancel)

	// Verify that Conn's context is a child of Transport's context
	transportCancel := transport.cancel
	transportCancel()

	// After cancelling the transport's context, the conn's context should also be cancelled
	select {
	case <-conn.ctx.Done():
		// Success - conn's context was cancelled
	case <-time.After(time.Second):
		t.Error("Conn's context was not cancelled when transport's context was cancelled")
	}
}

func TestSetAndGetPeerKey(t *testing.T) {
	mockQConn := mocks.NewMockQuicConnection()
	mockQConn.On("Context").Return(context.Background())
	transport := &Transport{
		ctx:    context.Background(),
		cancel: func() {},
	}

	conn := newConn(mockQConn, transport)

	pubKey, _, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	conn.SetPeerKey(pubKey)

	retrievedKey := conn.PeerKey()
	assert.Equal(t, pubKey, retrievedKey)
}

func TestOpenStream(t *testing.T) {
	// Test cases
	tests := []struct {
		name          string
		mockSetup     func(mockQConn *quicconn.MockQuicConnection) quic.Stream
		expectedError string
	}{
		{
			name: "Stream opens successfully",
			mockSetup: func(mockQConn *quicconn.MockQuicConnection) quic.Stream {
				mockStream := mocks.NewMockQuicStream()
				mockQConn.On("OpenStreamSync", mock.Anything).Return(mockStream, nil).Once()
				mockQConn.On("Context").Return(context.Background())
				return mockStream
			},
			expectedError: "",
		},
		{
			name: "Stream open fails",
			mockSetup: func(mockQConn *quicconn.MockQuicConnection) quic.Stream {
				mockQConn.On("OpenStreamSync", mock.Anything).Return(mocks.NewMockQuicStream(), errors.New("stream error")).Once()
				mockQConn.On("Context").Return(context.Background())
				return nil
			},
			expectedError: "failed to open QUIC stream: stream error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockQConn := mocks.NewMockQuicConnection()
			mockQConn.On("Context").Return(context.Background()).Once()
			transport := &Transport{
				ctx:    context.Background(),
				cancel: func() {},
			}

			conn := newConn(mockQConn, transport)
			expectedStream := tt.mockSetup(mockQConn)

			// Execute
			ctx := context.Background()
			stream, err := conn.OpenStream(ctx)

			if tt.expectedError != "" {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError)
				assert.Nil(t, stream)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, expectedStream, stream)
			}

			// Verify all expected calls were made
			mockQConn.AssertExpectations(t)
		})
	}
}

func TestAcceptStream(t *testing.T) {
	tests := []struct {
		name          string
		mockSetup     func(mockQConn *quicconn.MockQuicConnection) quic.Stream
		expectedError string
	}{
		{
			name: "Stream accepted successfully",
			mockSetup: func(mockQConn *quicconn.MockQuicConnection) quic.Stream {
				mockStream := mocks.NewMockQuicStream()
				mockQConn.On("AcceptStream", mock.Anything).Return(mockStream, nil).Once()
				mockQConn.On("Context").Return(context.Background())
				return mockStream
			},
			expectedError: "",
		},
		{
			name: "Stream accept fails",
			mockSetup: func(mockQConn *quicconn.MockQuicConnection) quic.Stream {
				mockQConn.On("AcceptStream", mock.Anything).Return(mocks.NewMockQuicStream(), errors.New("accept error")).Once()
				mockQConn.On("Context").Return(context.Background())
				return nil
			},
			expectedError: "failed to accept QUIC stream: accept error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockQConn := mocks.NewMockQuicConnection()
			mockQConn.On("Context").Return(context.Background())
			transport := &Transport{
				ctx:    context.Background(),
				cancel: func() {},
			}

			conn := newConn(mockQConn, transport)
			expectedStream := tt.mockSetup(mockQConn)

			// Execute
			stream, err := conn.AcceptStream()

			if tt.expectedError != "" {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError)
				assert.Nil(t, stream)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, expectedStream, stream)
			}

			// Verify all expected calls were made
			mockQConn.AssertExpectations(t)
		})
	}
}

func TestConnClose(t *testing.T) {
	mockQConn := mocks.NewMockQuicConnection()
	mockQConn.On("Context").Return(context.Background())
	mockQConn.On("CloseWithError", quic.ApplicationErrorCode(0), "").Return(nil)

	transport := &Transport{
		ctx:    context.Background(),
		cancel: func() {},
	}

	conn := newConn(mockQConn, transport)

	// Execute
	err := conn.Close()
	assert.NoError(t, err)

	// The context should be cancelled
	select {
	case <-conn.ctx.Done():
		// Success - context was cancelled
	default:
		t.Error("Context was not cancelled when connection was closed")
	}

	mockQConn.AssertExpectations(t)
}

func TestConnContextCancel(t *testing.T) {
	mockQConn := mocks.NewMockQuicConnection()
	mockQConn.On("Context").Return(context.Background())
	transport := &Transport{
		ctx:    context.Background(),
		cancel: func() {},
	}

	conn := newConn(mockQConn, transport)

	// Execute
	ctx := conn.Context()
	assert.NotNil(t, ctx)
	assert.Equal(t, conn.ctx, ctx)

	// Cancel the connection and verify the context is cancelled
	conn.cancel()

	select {
	case <-ctx.Done():
		// Success - context was cancelled
	default:
		t.Error("Returned context was not cancelled when connection was cancelled")
	}
}

// TestContextCancellationPropagation tests that cancellation propagates correctly from transport to connection
func TestContextCancellationPropagation(t *testing.T) {
	// Setup
	mockQConn := mocks.NewMockQuicConnection()
	mockQConn.On("Context").Return(context.Background())
	transportCtx, transportCancel := context.WithCancel(context.Background())
	transport := &Transport{
		ctx:    transportCtx,
		cancel: transportCancel,
	}

	conn := newConn(mockQConn, transport)

	// Cancel the transport context
	transportCancel()

	// Verify the conn context is also cancelled
	select {
	case <-conn.ctx.Done():
		// Success - context was cancelled
	case <-time.After(time.Second):
		t.Error("Conn context was not cancelled when transport context was cancelled")
	}
}

func TestRemoteConnectionClose(t *testing.T) {
	// Setup a mock QUIC connection with its own context
	qConnCtx, qConnCancel := context.WithCancel(context.Background())
	mockQConn := mocks.NewMockQuicConnection()
	mockQConn.On("Context").Return(qConnCtx)

	// Setup transport
	transportCtx, transportCancel := context.WithCancel(context.Background())
	defer transportCancel()

	transport := &Transport{
		ctx:    transportCtx,
		cancel: transportCancel,
	}

	// Create the connection
	conn := newConn(mockQConn, transport)

	// At this point, our conn should be "active"
	select {
	case <-conn.Context().Done():
		t.Fatal("Connection context should not be cancelled yet")
	default:
		// This is expected - context is still active
	}

	// Simulate remote connection closure by cancelling the QUIC connection context
	qConnCancel()

	// Give the goroutine time to react to the context cancellation
	timeoutCtx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	// Check that our connection context was cancelled as a result
	select {
	case <-conn.Context().Done():
		// Success - context was cancelled due to QUIC connection closure
	case <-timeoutCtx.Done():
		t.Fatal("Connection context was not cancelled after QUIC connection closure")
	}

	mockQConn.AssertExpectations(t)
}
