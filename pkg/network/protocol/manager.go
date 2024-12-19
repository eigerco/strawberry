// protocol/manager.go
package protocol

import (
	"crypto/tls"
	"fmt"
	"strings"

	"github.com/eigerco/strawberry/pkg/network/transport"
)

type Config struct {
	ChainHash       string
	IsBuilder       bool
	MaxBuilderSlots int
}

// Manager handles protocol-level connection management and implements transport.ConnectionHandler
type Manager struct {
	Registry *JAMNPRegistry
	config   Config
}

func NewManager(config Config) (*Manager, error) {
	if config.ChainHash == "" {
		return nil, fmt.Errorf("chain hash required")
	}

	// Validate chain hash format upfront using the ALPN utilities
	if err := ValidateALPNProtocol(NewProtocolID(config.ChainHash, false).String()); err != nil {
		return nil, fmt.Errorf("invalid chain hash format: %w", err)
	}

	return &Manager{
		Registry: NewJAMNPRegistry(),
		config:   config,
	}, nil
}

// OnConnection implements transport.ConnectionHandler
func (m *Manager) OnConnection(conn *transport.Conn) error {
	// Protocol connection creation could fail due to invalid parameters
	protoConn, err := m.setupProtocolConn(conn)
	if err != nil {
		return fmt.Errorf("protocol connection setup failed: %w", err)
	}
	go m.handleStreams(protoConn)

	return nil
}
func (m *Manager) handleStreams(protoConn *ProtocolConn) {
	defer protoConn.Close() // Ensure proper cleanup of the connection

	for {
		// Attempt to accept an incoming stream
		streamErr := protoConn.AcceptStream()
		if streamErr != nil {
			// Check if the connection's context has been canceled
			if protoConn.tConn.Context().Err() != nil {
				fmt.Println("Connection closed: context done")
				return
			}

			// Explicitly handle QUIC timeout errors
			if isTimeoutError(streamErr) {
				fmt.Println("Connection timed out due to inactivity")
				protoConn.Close() // Close the connection explicitly
				return
			}

			// Log other errors and continue listening
			fmt.Printf("Stream accept error: %v\n", streamErr)
			continue
		}
	}
}

// isTimeoutError checks if the error is a timeout error
func isTimeoutError(err error) bool {
	return err != nil && strings.Contains(err.Error(), "timeout: no recent network activity")
}

func (m *Manager) setupProtocolConn(conn *transport.Conn) (*ProtocolConn, error) {
	if conn == nil {
		return nil, fmt.Errorf("invalid connection")
	}

	protoConn := NewProtocolConn(conn, m.Registry)

	return protoConn, nil
}

// GetProtocols implements transport.ConnectionHandler
func (m *Manager) GetProtocols() []string {
	return AcceptableProtocols(m.config.ChainHash)
}

// ValidateConnection implements transport.ConnectionHandler
func (m *Manager) ValidateConnection(tlsState tls.ConnectionState) error {
	if tlsState.NegotiatedProtocol == "" {
		return fmt.Errorf("no protocol negotiated")
	}

	// Parse and validate the protocol format
	protocolID, err := ParseProtocolID(tlsState.NegotiatedProtocol)
	if err != nil {
		return fmt.Errorf("invalid protocol: %w", err)
	}

	// Verify chain hash matches our configuration
	if protocolID.ChainHash != m.config.ChainHash {
		return fmt.Errorf("chain hash mismatch: got %s, want %s",
			protocolID.ChainHash, m.config.ChainHash)
	}

	// Verify builder status matches our configuration
	if protocolID.IsBuilder && !m.config.IsBuilder {
		return fmt.Errorf("builder connections not accepted")
	}

	return nil
}

func (m *Manager) WrapConnection(conn *transport.Conn) *ProtocolConn {
	return NewProtocolConn(conn, m.Registry)
}
