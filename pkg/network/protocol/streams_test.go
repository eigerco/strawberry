package protocol

import (
	"context"

	"github.com/eigerco/strawberry/internal/crypto/ed25519"

	"errors"
	"testing"

	"github.com/eigerco/strawberry/pkg/network/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewJAMNPRegistry(t *testing.T) {
	registry := NewJAMNPRegistry()
	assert.NotNil(t, registry)
	assert.NotNil(t, registry.handlers)
	assert.Empty(t, registry.handlers)
}

func TestRegisterHandler(t *testing.T) {
	registry := NewJAMNPRegistry()
	mockHandler := mocks.NewMockStreamHandler()

	// Register handlers for different stream kinds
	registry.RegisterHandler(StreamKindBlockAnnouncement, mockHandler)
	registry.RegisterHandler(StreamKindBlockRequest, mockHandler)

	assert.Len(t, registry.handlers, 2)

	// Verify the handlers were registered correctly
	handler, err := registry.GetHandler(StreamKindBlockAnnouncement)
	require.NoError(t, err)
	assert.Same(t, mockHandler, handler)

	handler, err = registry.GetHandler(StreamKindBlockRequest)
	require.NoError(t, err)
	assert.Same(t, mockHandler, handler)
}

func TestGetHandler(t *testing.T) {
	registry := NewJAMNPRegistry()
	mockHandler := mocks.NewMockStreamHandler()

	// Register a handler
	registry.RegisterHandler(StreamKindBlockAnnouncement, mockHandler)

	// Test cases
	tests := []struct {
		name      string
		kind      StreamKind
		expectErr bool
	}{
		{
			name:      "Get registered handler",
			kind:      StreamKindBlockAnnouncement,
			expectErr: false,
		},
		{
			name:      "Get unregistered handler",
			kind:      StreamKindBlockRequest,
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler, err := registry.GetHandler(tt.kind)

			if tt.expectErr {
				assert.Error(t, err)
				assert.Nil(t, handler)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, handler)
				assert.Same(t, mockHandler, handler)
			}
		})
	}
}

func TestValidateKind(t *testing.T) {
	registry := NewJAMNPRegistry()

	// Test cases
	tests := []struct {
		name      string
		kind      byte
		expectErr bool
	}{
		{
			name:      "Valid UP stream kind",
			kind:      byte(StreamKindBlockAnnouncement),
			expectErr: false,
		},
		{
			name:      "Valid CE stream kind",
			kind:      byte(StreamKindBlockRequest),
			expectErr: false,
		},
		{
			name:      "Valid highest defined kind",
			kind:      byte(StreamKindJudgmentPublish),
			expectErr: false,
		},
		{
			name:      "Invalid kind (too high)",
			kind:      byte(StreamKindJudgmentPublish) + 1,
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := registry.ValidateKind(tt.kind)

			if tt.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestStreamKindIsUniquePersistent(t *testing.T) {
	// Test cases
	tests := []struct {
		name               string
		kind               StreamKind
		isUniquePersistent bool
	}{
		{
			name:               "UP stream kind",
			kind:               StreamKindBlockAnnouncement,
			isUniquePersistent: true,
		},
		{
			name:               "CE stream kind (minimum)",
			kind:               StreamKindBlockRequest,
			isUniquePersistent: false,
		},
		{
			name:               "CE stream kind (maximum)",
			kind:               StreamKindJudgmentPublish,
			isUniquePersistent: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.kind.IsUniquePersistent()
			assert.Equal(t, tt.isUniquePersistent, result)
		})
	}
}

func TestRegistryWithHandlerImplementation(t *testing.T) {
	registry := NewJAMNPRegistry()
	mockHandler := mocks.NewMockStreamHandler()
	mockStream := mocks.NewMockQuicStream()
	ctx := context.Background()
	pubKey, _, _ := ed25519.GenerateKey(nil)

	// Configure mock behavior
	mockHandler.On("HandleStream", ctx, mockStream, pubKey).Return(nil)
	mockStream.On("Context").Return(ctx)

	// Register handler
	registry.RegisterHandler(StreamKindBlockAnnouncement, mockHandler)

	// Get handler and use it
	handler, err := registry.GetHandler(StreamKindBlockAnnouncement)
	require.NoError(t, err)

	err = handler.HandleStream(ctx, mockStream, pubKey)
	assert.NoError(t, err)

	// Verify mock was called correctly
	mockHandler.AssertExpectations(t)
}

func TestRegistryWithErrorHandling(t *testing.T) {
	// Setup
	registry := NewJAMNPRegistry()
	mockHandler := mocks.NewMockStreamHandler()
	mockStream := mocks.NewMockQuicStream()
	ctx := context.Background()
	pubKey, _, _ := ed25519.GenerateKey(nil)
	expectedErr := errors.New("stream handling error")

	// Configure mock behavior to return an error
	mockHandler.On("HandleStream", ctx, mockStream, pubKey).Return(expectedErr)
	mockStream.On("Context").Return(ctx)

	// Register handler
	registry.RegisterHandler(StreamKindBlockRequest, mockHandler)

	// Get handler and use it
	handler, err := registry.GetHandler(StreamKindBlockRequest)
	require.NoError(t, err)

	// Call handler and check that it returns the expected error
	err = handler.HandleStream(ctx, mockStream, pubKey)
	assert.Error(t, err)
	assert.Equal(t, expectedErr, err)

	// Verify mock was called correctly
	mockHandler.AssertExpectations(t)
}

func TestHandlerReplacement(t *testing.T) {
	registry := NewJAMNPRegistry()
	mockHandler1 := mocks.NewMockStreamHandler()
	mockHandler2 := mocks.NewMockStreamHandler()

	// Register first handler
	registry.RegisterHandler(StreamKindBlockAnnouncement, mockHandler1)

	// Check it was registered
	handler, err := registry.GetHandler(StreamKindBlockAnnouncement)
	require.NoError(t, err)
	assert.Same(t, mockHandler1, handler)

	// Replace with second handler
	registry.RegisterHandler(StreamKindBlockAnnouncement, mockHandler2)

	// Check it was replaced
	handler, err = registry.GetHandler(StreamKindBlockAnnouncement)
	require.NoError(t, err)
	assert.Same(t, mockHandler2, handler)
}
