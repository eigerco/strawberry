package protocol

import (
	"context"
	"crypto/tls"
	"errors"
	"testing"
	"time"

	"github.com/eigerco/strawberry/pkg/network/mocks"
	"github.com/quic-go/quic-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func createTestManager(t *testing.T) *Manager {
	testChainHash := "abcd1234"
	config := Config{
		ChainHash:       testChainHash,
		IsBuilder:       false,
		MaxBuilderSlots: 10,
	}

	manager, err := NewManager(config)
	assert.NoError(t, err)
	assert.NotNil(t, manager)
	return manager
}
func TestManager_OnConnection(t *testing.T) {
	manager := createTestManager(t)

	// Create mock transport connection
	mockConn := mocks.NewMockTransportConn()

	// Setup mock to handle AcceptStream call
	mockStream := mocks.NewMockQuicStream()
	mockStream.On("Read", mock.Anything).Return(1, nil).Run(func(args mock.Arguments) {
		// Simulate reading a stream kind byte
		b := args.Get(0).([]byte)
		b[0] = byte(StreamKindBlockAnnouncement)
	})

	// Configure the mock to return our mock stream
	mockConn.On("AcceptStream").Return(mockStream, nil)
	mockConn.On("Context").Return(mockConn.Context())
	mockConn.On("PeerKey").Return(mockConn.PeerKey())

	ctx := mockConn.Context()

	// Register a mock handler for the stream kind
	mockHandler := mocks.NewMockStreamHandler()
	mockHandler.On("HandleStream", ctx, mockStream, mockConn.PeerKey()).Return(nil)
	manager.Registry.RegisterHandler(StreamKindBlockAnnouncement, mockHandler)

	// Call the method under test
	protoConn := manager.OnConnection(mockConn)
	assert.NotNil(t, protoConn)

	// Wait for the handleStreams goroutine to process
	time.Sleep(100 * time.Millisecond)

	// Verify expected mock calls were made
	mockConn.AssertExpectations(t)
	mockStream.AssertExpectations(t)
	mockHandler.AssertExpectations(t)
}

func TestHandleStreams_Success(t *testing.T) {
	manager := createTestManager(t)

	// Create controlled context
	mockCtx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Setup mock connection
	mockConn := mocks.NewMockTransportConn()
	mockConn.On("Context").Return(mockCtx)
	mockConn.On("PeerKey").Return(mockConn.PeerKey())
	// Setup mock stream
	mockStream := mocks.NewMockQuicStream()
	mockStream.On("Read", mock.Anything).Return(1, nil).Run(func(args mock.Arguments) {
		b := args.Get(0).([]byte)
		b[0] = byte(StreamKindBlockAnnouncement)
	})

	// Configure successful AcceptStream followed by an error
	mockConn.On("AcceptStream").Return(mockStream, nil).Once()
	mockConn.On("AcceptStream").Return(nil, errors.New("test complete"))

	// After second call fails, we may check context
	mockConn.On("Close").Return(nil)

	// Track handler invocation
	handlerCalled := make(chan struct{}, 1)

	// Register mock handler
	mockHandler := mocks.NewMockStreamHandler()
	mockHandler.On("HandleStream", mock.Anything, mockStream, mock.Anything).Return(nil).
		Run(func(args mock.Arguments) {
			handlerCalled <- struct{}{}
		})
	manager.Registry.RegisterHandler(StreamKindBlockAnnouncement, mockHandler)

	// Start handleStreams goroutine
	protoConn := manager.OnConnection(mockConn)
	assert.NotNil(t, protoConn)

	// Verify handler was called
	select {
	case <-handlerCalled:
		// Success
	case <-time.After(300 * time.Millisecond):
		t.Fatal("Handler was not called within timeout")
	}

	// Wait for the second AcceptStream call to complete
	time.Sleep(100 * time.Millisecond)

	// Cancel context to stop the goroutine cleanly
	cancel()
	// Wait for protocol connection to close
	time.Sleep(100 * time.Millisecond)
	// Verify expected mock calls
	mockConn.AssertExpectations(t)
	mockStream.AssertExpectations(t)
	mockHandler.AssertExpectations(t)
}

func TestHandleStreams_StreamError(t *testing.T) {
	manager := createTestManager(t)

	// Create controlled context
	mockCtx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Setup mock connection
	mockConn := mocks.NewMockTransportConn()
	mockConn.On("Context").Return(mockCtx)
	mockConn.On("Close").Return(nil)

	// Return stream error first, then cancel context to exit loop
	streamErr := errors.New("stream error")
	mockConn.On("AcceptStream").Return(nil, streamErr).Once()

	// After error, we should try to accept another stream, but we'll
	// cancel the context before that happens
	mockConn.On("AcceptStream").Return(nil, errors.New("waiting")).Maybe()

	// Start handleStreams goroutine
	protoConn := manager.OnConnection(mockConn)
	assert.NotNil(t, protoConn)

	// Let goroutine process the error
	time.Sleep(100 * time.Millisecond)

	// Cancel context to stop the goroutine cleanly
	cancel()
	// Wait for protocol connection to close
	time.Sleep(100 * time.Millisecond)
	// Verify expected mock calls
	mockConn.AssertExpectations(t)
}

func TestHandleStreams_TimeoutError(t *testing.T) {
	manager := createTestManager(t)

	// Setup mock connection
	mockConn := mocks.NewMockTransportConn()
	mockCtx := context.Background()
	mockConn.On("Context").Return(mockCtx)

	// Return timeout error
	timeoutErr := &quic.ApplicationError{
		ErrorCode:    0,
		ErrorMessage: "timeout: no recent network activity",
	}
	mockConn.On("AcceptStream").Return(nil, timeoutErr).Once()

	// Since this is a timeout, Close should be called
	mockConn.On("Close").Return(nil)

	// Start handleStreams goroutine
	protoConn := manager.OnConnection(mockConn)
	assert.NotNil(t, protoConn)

	// Wait for goroutine to process timeout error and close connection
	time.Sleep(100 * time.Millisecond)

	// Verify expected mock calls
	mockConn.AssertExpectations(t)
	mockConn.AssertNumberOfCalls(t, "Close", 2) //2 times because handleStreams has a defer protoConn.Close()
}

func TestHandleStreams_ContextCancellation(t *testing.T) {
	manager := createTestManager(t)

	// Create context we can control
	mockCtx, cancel := context.WithCancel(context.Background())

	// Setup mock connection
	mockConn := mocks.NewMockTransportConn()
	mockConn.On("Context").Return(mockCtx)
	mockConn.On("AcceptStream").Return(nil, errors.New("waiting"))
	mockConn.On("Close").Return(nil).Once()

	// Start handleStreams goroutine
	protoConn := manager.OnConnection(mockConn)
	assert.NotNil(t, protoConn)

	// Cancel context to trigger early exit
	cancel()

	// Wait for goroutine to exit
	time.Sleep(100 * time.Millisecond)

	// Verify expectations
	mockConn.AssertExpectations(t)
}

func TestManager_ValidateConnection(t *testing.T) {
	testChainHash := "abcd1234"

	t.Run("Valid non-builder protocol", func(t *testing.T) {
		// Setup
		config := Config{
			ChainHash:       testChainHash,
			IsBuilder:       false,
			MaxBuilderSlots: 10,
		}

		manager, err := NewManager(config)
		assert.NoError(t, err)

		// Create TLS state with valid protocol
		tlsState := tls.ConnectionState{
			NegotiatedProtocol: NewProtocolID(testChainHash, false).String(),
		}

		// Test
		err = manager.ValidateConnection(tlsState)
		assert.NoError(t, err)
	})

	t.Run("Valid builder protocol for builder node", func(t *testing.T) {
		// Setup
		config := Config{
			ChainHash:       testChainHash,
			IsBuilder:       true,
			MaxBuilderSlots: 10,
		}

		manager, err := NewManager(config)
		assert.NoError(t, err)

		// Create TLS state with valid builder protocol
		tlsState := tls.ConnectionState{
			NegotiatedProtocol: NewProtocolID(testChainHash, true).String(),
		}

		// Test
		err = manager.ValidateConnection(tlsState)
		assert.NoError(t, err)
	})

	t.Run("Empty protocol", func(t *testing.T) {
		config := Config{
			ChainHash:       testChainHash,
			IsBuilder:       false,
			MaxBuilderSlots: 10,
		}

		manager, err := NewManager(config)
		assert.NoError(t, err)

		// Create TLS state with empty protocol
		tlsState := tls.ConnectionState{
			NegotiatedProtocol: "",
		}

		// Test
		err = manager.ValidateConnection(tlsState)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "no protocol negotiated")
	})

	t.Run("Invalid protocol format", func(t *testing.T) {
		config := Config{
			ChainHash:       testChainHash,
			IsBuilder:       false,
			MaxBuilderSlots: 10,
		}

		manager, err := NewManager(config)
		assert.NoError(t, err)

		// Create TLS state with invalid protocol
		tlsState := tls.ConnectionState{
			NegotiatedProtocol: "invalid-protocol",
		}

		// Test
		err = manager.ValidateConnection(tlsState)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid protocol")
	})

	t.Run("Chain hash mismatch", func(t *testing.T) {
		config := Config{
			ChainHash:       testChainHash,
			IsBuilder:       false,
			MaxBuilderSlots: 10,
		}

		manager, err := NewManager(config)
		assert.NoError(t, err)

		// Create TLS state with different chain hash
		differentChainHash := "abcd5678"
		tlsState := tls.ConnectionState{
			NegotiatedProtocol: NewProtocolID(differentChainHash, false).String(),
		}

		// Test
		err = manager.ValidateConnection(tlsState)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "chain hash mismatch")
		assert.Contains(t, err.Error(), differentChainHash)
		assert.Contains(t, err.Error(), testChainHash)
	})

	t.Run("Builder protocol rejected by non-builder node", func(t *testing.T) {
		// Setup
		config := Config{
			ChainHash:       testChainHash,
			IsBuilder:       false, // Non-builder node
			MaxBuilderSlots: 10,
		}

		manager, err := NewManager(config)
		assert.NoError(t, err)

		// Create TLS state with builder protocol
		tlsState := tls.ConnectionState{
			NegotiatedProtocol: NewProtocolID(testChainHash, true).String(), // Builder protocol
		}

		// Test
		err = manager.ValidateConnection(tlsState)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "builder connections not accepted")
	})
}
