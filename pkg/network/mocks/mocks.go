package mocks

import (
	"github.com/eigerco/strawberry/pkg/network/mocks/quicconn"
	"github.com/eigerco/strawberry/pkg/network/mocks/stream"
	"github.com/eigerco/strawberry/pkg/network/mocks/transport"
)

func NewMockQuicConnection() *quicconn.MockQuicConnection {
	return quicconn.NewMockQuicConnection()
}

func NewMockQuicStream() *stream.MockQuicStream {
	return stream.NewMockQuicStream()
}

func NewMockTransportConn() *transport.MockTransportConn {
	return transport.NewMockTransportConn()
}

func NewMockStreamHandler() *stream.MockStreamHandler {
	return stream.NewMockStreamHandler()
}
