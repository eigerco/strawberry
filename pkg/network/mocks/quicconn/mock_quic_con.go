package quicconn

import (
	"context"
	"net"

	"github.com/quic-go/quic-go"
	"github.com/stretchr/testify/mock"
)

// MockQuicConnection mocks the quic.Connection interface for testing
type MockQuicConnection struct {
	mock.Mock
}

func NewMockQuicConnection() *MockQuicConnection {
	return new(MockQuicConnection)
}

func (m *MockQuicConnection) AcceptStream(ctx context.Context) (quic.Stream, error) {
	args := m.Called(ctx)
	return args.Get(0).(quic.Stream), args.Error(1)
}

func (m *MockQuicConnection) AcceptUniStream(ctx context.Context) (quic.ReceiveStream, error) {
	args := m.Called(ctx)
	return args.Get(0).(quic.ReceiveStream), args.Error(1)
}

func (m *MockQuicConnection) OpenStream() (quic.Stream, error) {
	args := m.Called()
	return args.Get(0).(quic.Stream), args.Error(1)
}

func (m *MockQuicConnection) OpenStreamSync(ctx context.Context) (quic.Stream, error) {
	args := m.Called(ctx)
	return args.Get(0).(quic.Stream), args.Error(1)
}

func (m *MockQuicConnection) OpenUniStream() (quic.SendStream, error) {
	args := m.Called()
	return args.Get(0).(quic.SendStream), args.Error(1)
}

func (m *MockQuicConnection) OpenUniStreamSync(ctx context.Context) (quic.SendStream, error) {
	args := m.Called(ctx)
	return args.Get(0).(quic.SendStream), args.Error(1)
}

func (m *MockQuicConnection) LocalAddr() net.Addr {
	args := m.Called()
	return args.Get(0).(net.Addr)
}

func (m *MockQuicConnection) RemoteAddr() net.Addr {
	args := m.Called()
	return args.Get(0).(net.Addr)
}

func (m *MockQuicConnection) CloseWithError(code quic.ApplicationErrorCode, reason string) error {
	args := m.Called(code, reason)
	return args.Error(0)
}

func (m *MockQuicConnection) ConnectionState() quic.ConnectionState {
	args := m.Called()
	return args.Get(0).(quic.ConnectionState)
}

func (m *MockQuicConnection) Context() context.Context {
	args := m.Called()
	return args.Get(0).(context.Context)
}

func (m *MockQuicConnection) SendDatagram(b []byte) error {
	args := m.Called(b)
	return args.Error(0)
}

func (m *MockQuicConnection) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	args := m.Called(ctx)
	return args.Get(0).([]byte), args.Error(1)
}
