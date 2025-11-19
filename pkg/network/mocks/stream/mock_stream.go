package stream

import (
	"context"

	"github.com/eigerco/strawberry/internal/crypto/ed25519"

	"time"

	"github.com/quic-go/quic-go"
	"github.com/stretchr/testify/mock"
)

// MockQuicStream implements the quic.Stream interface for testing
type MockQuicStream struct {
	mock.Mock
}

func NewMockQuicStream() *MockQuicStream {
	return &MockQuicStream{}
}

func (m *MockQuicStream) Read(p []byte) (int, error) {
	args := m.Called(p)
	return args.Int(0), args.Error(1)
}

func (m *MockQuicStream) Write(p []byte) (int, error) {
	args := m.Called(p)
	return args.Int(0), args.Error(1)
}

func (m *MockQuicStream) Close() error {
	args := m.Called()
	return args.Error(0)
}

func (m *MockQuicStream) CancelRead(quic.StreamErrorCode) {
	m.Called()
}
func (m *MockQuicStream) CancelWrite(quic.StreamErrorCode) {

	m.Called()
}

func (m *MockQuicStream) SetReadDeadline(t time.Time) error {
	args := m.Called(t)
	return args.Error(0)
}

func (m *MockQuicStream) SetWriteDeadline(t time.Time) error {
	args := m.Called(t)
	return args.Error(0)
}

func (m *MockQuicStream) SetDeadline(t time.Time) error {
	args := m.Called(t)
	return args.Error(0)
}

func (m *MockQuicStream) StreamID() quic.StreamID {
	args := m.Called()
	return args.Get(0).(quic.StreamID)
}

func (m *MockQuicStream) Context() context.Context {
	args := m.Called()
	if args.Get(0) == nil {
		return context.Background()
	}
	return args.Get(0).(context.Context)
}

// MockStreamHandler is a mock implementation of StreamHandler for testing
type MockStreamHandler struct {
	mock.Mock
}

func NewMockStreamHandler() *MockStreamHandler {
	return &MockStreamHandler{}
}

func (m *MockStreamHandler) HandleStream(ctx context.Context, stream quic.Stream, peerKey ed25519.PublicKey) error {
	args := m.Called(ctx, stream, peerKey)
	return args.Error(0)
}
