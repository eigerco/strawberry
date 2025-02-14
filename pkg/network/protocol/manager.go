package protocol

import (
	"crypto/tls"
	"fmt"
	"strings"

	"github.com/eigerco/strawberry/pkg/network/transport"
)

// Config represents the configuration for a protocol Manager
type Config struct {
	// ChainHash is the identifier of the blockchain network
	ChainHash string
	// IsBuilder indicates if this node is a block builder
	IsBuilder bool
	// MaxBuilderSlots specifies the maximum number of concurrent builder connections
	MaxBuilderSlots int
}

// Manager handles protocol-level connection management and implements transport.ConnectionHandler.
// It manages protocol connections, stream handling, and protocol validation.
type Manager struct {
	Registry *JAMNPRegistry
	config   Config
}

// NewManager creates a new protocol Manager with the given configuration.
// It validates the configuration and initializes a new JAMNPRegistry.
// Returns an error if the chain hash is empty or invalid.
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

// OnConnection is called when a new transport connection is established.
// It sets up a protocol connection and starts a stream handling goroutine.
func (m *Manager) OnConnection(conn *transport.Conn) *ProtocolConn {
	protoConn := NewProtocolConn(conn, m.Registry)
	go m.handleStreams(protoConn)
	return protoConn
}

// handleStreams manages the lifecycle of streams for a protocol connection.
// It continuously accepts new streams and handles connection closure and timeouts.
func (m *Manager) handleStreams(protoConn *ProtocolConn) {
	defer protoConn.Close() // Ensure proper cleanup of the connection

	for {
		// Attempt to accept an incoming stream
		streamErr := protoConn.AcceptStream()
		if streamErr != nil {
			// Check if the connection's context has been canceled
			if protoConn.TConn.Context().Err() != nil {
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
			//fmt.Printf("Stream accept error: %v\n", streamErr)
			continue
		}
	}
}

// isTimeoutError determines if an error represents a connection timeout.
// Returns true if the error message indicates no recent network activity.
func isTimeoutError(err error) bool {
	return err != nil && strings.Contains(err.Error(), "timeout: no recent network activity")
}

// GetProtocols returns the list of supported ALPN protocol strings.
// The returned protocols include both builder and non-builder variants.
// Implements the transport.ConnectionHandler interface.
func (m *Manager) GetProtocols() []string {
	return AcceptableProtocols(m.config.ChainHash)
}

// ValidateConnection validates a new TLS connection's protocol negotiation.
// It checks the negotiated protocol matches the expected format and configuration.
// Implements the transport.ConnectionHandler interface.
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
