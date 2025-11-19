package transport

import (
	"context"

	"github.com/eigerco/strawberry/internal/crypto/ed25519"

	"net"

	"github.com/eigerco/strawberry/pkg/network/mocks/quicconn"
	"github.com/quic-go/quic-go"
	"github.com/stretchr/testify/mock"
)

// MockTransportConn mocks the transport.Conn struct for testing
type MockTransportConn struct {
	mock.Mock
	ctx     context.Context
	cancel  context.CancelFunc
	peerKey ed25519.PublicKey
	qConn   *quicconn.MockQuicConnection
}

func NewMockTransportConn() *MockTransportConn {
	ctx, cancel := context.WithCancel(context.Background())
	peerKey, _, _ := ed25519.GenerateKey(nil)

	mockQConn := quicconn.NewMockQuicConnection()
	// Setup default behaviors for the mock
	mockCtx := context.Background()
	mockQConn.On("Context").Return(mockCtx).Maybe()

	// Set up a default remote address
	mockAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1234}
	mockQConn.On("RemoteAddr").Return(mockAddr).Maybe()

	return &MockTransportConn{
		ctx:     ctx,
		cancel:  cancel,
		peerKey: peerKey,
		qConn:   mockQConn,
	}
}

func (m *MockTransportConn) OpenStream(ctx context.Context) (quic.Stream, error) {
	args := m.Called(ctx)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(quic.Stream), args.Error(1)
}

func (m *MockTransportConn) AcceptStream() (quic.Stream, error) {
	args := m.Called()
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(quic.Stream), args.Error(1)
}

func (m *MockTransportConn) QConn() quic.Connection {
	args := m.Called()
	if args.Get(0) != nil {
		return args.Get(0).(quic.Connection)
	}
	return m.qConn
}

func (m *MockTransportConn) Context() context.Context {
	args := m.Called()
	if len(args) > 0 && args.Get(0) != nil {
		return args.Get(0).(context.Context)
	}
	return m.ctx
}

func (m *MockTransportConn) PeerKey() ed25519.PublicKey {
	args := m.Called()
	if len(args) > 0 && args.Get(0) != nil {
		return args.Get(0).(ed25519.PublicKey)
	}
	return m.peerKey
}

func (m *MockTransportConn) Close() error {
	m.cancel()
	args := m.Called()
	if args.Error(0) != nil {
		return args.Error(0)
	}
	return nil
}

// SetupQConnMock sets up the QConn mock with specific expectations
func (m *MockTransportConn) SetupQConnMock(remoteAddr net.Addr) {
	m.qConn.On("RemoteAddr").Return(remoteAddr)
}
