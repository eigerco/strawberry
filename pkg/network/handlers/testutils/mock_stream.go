package testutils

import (
	"bytes"
	"context"
	"time"

	"github.com/quic-go/quic-go"
)

type MockStream struct {
	Buffer        *bytes.Buffer
	CloseCalled   bool
	ReadDeadline  time.Time
	WriteDeadline time.Time
	CanceledRead  bool
	CanceledWrite bool
}

func NewMockStream() *MockStream {
	return &MockStream{
		Buffer: new(bytes.Buffer),
	}
}

func (fs *MockStream) StreamID() quic.StreamID {
	return 1
}

func (fs *MockStream) Read(p []byte) (int, error) {
	return fs.Buffer.Read(p)
}

func (fs *MockStream) Write(p []byte) (int, error) {
	return fs.Buffer.Write(p)
}

func (fs *MockStream) Close() error {
	fs.CloseCalled = true
	return nil
}

func (fs *MockStream) CancelRead(code quic.StreamErrorCode) {
	fs.CanceledRead = true
}

func (fs *MockStream) CancelWrite(code quic.StreamErrorCode) {
	fs.CanceledWrite = true
}

func (fs *MockStream) Context() context.Context {
	return context.Background()
}

func (fs *MockStream) SetDeadline(t time.Time) error {
	fs.ReadDeadline = t
	fs.WriteDeadline = t
	return nil
}

func (fs *MockStream) SetReadDeadline(t time.Time) error {
	fs.ReadDeadline = t
	return nil
}

func (fs *MockStream) SetWriteDeadline(t time.Time) error {
	fs.WriteDeadline = t
	return nil
}
