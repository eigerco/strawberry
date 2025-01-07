package transport

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
)

// MaxIdleTimeout defines the maximum duration a connection can be idle before timing out
const MaxIdleTimeout = 30 * time.Minute

// StreamHandler processes individual QUIC streams within a connection
type StreamHandler interface {
	HandleStream(ctx context.Context, stream quic.Stream) error
}

// StreamRegistry manages stream handlers and validates stream kinds
type StreamRegistry interface {
	// GetHandler returns the handler for a given stream kind byte
	GetHandler(kindByte byte) (StreamHandler, error)
	// ValidateKind checks if a stream kind byte is valid
	ValidateKind(kindByte byte) error
}

// CertValidator performs TLS certificate validation and public key extraction
type CertValidator interface {
	// ValidateCertificate checks if a certificate meets required criteria
	ValidateCertificate(cert *x509.Certificate) error
	// ExtractPublicKey retrieves the Ed25519 public key from a certificate
	ExtractPublicKey(cert *x509.Certificate) (ed25519.PublicKey, error)
}

// ProtocolManager handles ALPN protocol negotiation and validation
type ProtocolManager interface {
	// AcceptableProtocols returns valid protocol strings for a chain
	AcceptableProtocols(chainHash string) []string
	// NewProtocolID creates a protocol identifier string
	NewProtocolID(chainHash string, isBuilder bool) string
	// ValidateProtocol checks if a protocol string is valid
	ValidateProtocol(protocol string) error
}

// ConnectionHandler processes new connections and validates their protocols
type ConnectionHandler interface {
	// OnConnection is called when a new connection is established
	OnConnection(conn *Conn) error
	// GetProtocols returns supported ALPN protocol strings
	GetProtocols() []string
	// ValidateConnection verifies TLS connection parameters
	ValidateConnection(tlsState tls.ConnectionState) error
}

// Config contains all configuration parameters for a Transport
type Config struct {
	PublicKey     ed25519.PublicKey  // Node's public key
	PrivateKey    ed25519.PrivateKey // Node's private key
	TLSCert       *tls.Certificate   // TLS certificate
	ListenAddr    string             // Address to listen on
	CertValidator CertValidator      // Certificate validator
	Handler       ConnectionHandler  // Connection handler
}

// Transport manages QUIC connections and their lifecycles
type Transport struct {
	config   Config
	listener *quic.Listener
	mu       sync.RWMutex
	conns    map[string]*Conn // Active connections mapped by peer key
	ctx      context.Context
	cancel   context.CancelFunc
	done     chan struct{} // For clean shutdown of accept loop
}

// NewTransport creates and configures a new transport instance.
// Returns an error if any required configuration is missing or invalid.
func NewTransport(config Config) (*Transport, error) {
	if config.TLSCert == nil {
		return nil, fmt.Errorf("TLS certificate required")
	}
	if config.CertValidator == nil {
		return nil, fmt.Errorf("certificate validator required")
	}
	if config.Handler == nil {
		return nil, fmt.Errorf("connection handler required")
	}

	// Verify the certificate
	if err := config.CertValidator.ValidateCertificate(config.TLSCert.Leaf); err != nil {
		return nil, ErrInvalidCertificate
	}

	return &Transport{
		config: config,
		conns:  make(map[string]*Conn),
	}, nil
}

// Start initializes the transport listener and begins accepting connections.
// Returns an error if starting the listener fails.
func (t *Transport) Start() error {
	tlsConfig := &tls.Config{
		Certificates:       []tls.Certificate{*t.config.TLSCert},
		NextProtos:         t.config.Handler.GetProtocols(),
		ClientAuth:         tls.RequireAnyClientCert,
		MinVersion:         tls.VersionTLS13,
		InsecureSkipVerify: true,
		VerifyConnection: func(cs tls.ConnectionState) error {
			fmt.Printf("Negotiated Protocol: %s\n", cs.NegotiatedProtocol)
			if len(cs.PeerCertificates) == 0 {
				return fmt.Errorf("%w: no peer certificate provided", ErrInvalidCertificate)
			}
			cert := cs.PeerCertificates[0]
			if err := t.config.CertValidator.ValidateCertificate(cert); err != nil {
				return fmt.Errorf("%w: %v", ErrInvalidCertificate, err)
			}
			if err := t.config.Handler.ValidateConnection(cs); err != nil {
				return fmt.Errorf("connection validation failed: %v", err)
			}
			return nil
		},
	}

	listener, err := quic.ListenAddr(t.config.ListenAddr, tlsConfig, &quic.Config{
		EnableDatagrams: true,
		MaxIdleTimeout:  MaxIdleTimeout,
	})
	if err != nil {
		return fmt.Errorf("%w: %v", ErrListenerFailed, err)
	}

	t.ctx, t.cancel = context.WithCancel(context.Background())
	t.listener = listener
	t.done = make(chan struct{})
	go func() {
		t.acceptLoop()
		close(t.done)
	}()
	return nil
}

// Stop gracefully shuts down the transport and all active connections.
// Waits for the accept loop to finish before returning.
func (t *Transport) Stop() error {
	// Cancel the accept loop
	t.cancel()

	// Close all active connections
	t.mu.Lock()
	for _, conn := range t.conns {
		if err := conn.Close(); err != nil {
			fmt.Printf("Failed to close connection: %v\n", err)
		}
	}
	// Clear the connection map
	t.conns = make(map[string]*Conn)
	t.mu.Unlock()

	// Close the listener
	if t.listener != nil {
		if err := t.listener.Close(); err != nil {
			return fmt.Errorf("failed to close listener: %w", err)
		}
	}

	// Wait for the accept loop to finish
	<-t.done
	return nil
}

// Connect initiates a connection to a remote peer.
// Returns the new connection or an error if connection fails.
func (t *Transport) Connect(addr string) (*Conn, error) {
	tlsConf := &tls.Config{
		Certificates:       []tls.Certificate{*t.config.TLSCert},
		NextProtos:         t.config.Handler.GetProtocols(),
		ClientAuth:         tls.RequireAnyClientCert,
		MinVersion:         tls.VersionTLS13,
		InsecureSkipVerify: true,
		VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			c, err := x509.ParseCertificate(rawCerts[0])
			if err != nil {
				return fmt.Errorf("%w: %v", ErrInvalidCertificate, err)
			}
			if err := t.config.CertValidator.ValidateCertificate(c); err != nil {
				return fmt.Errorf("%w: %v", ErrInvalidCertificate, err)
			}
			return nil
		},
	}

	quicConn, err := quic.DialAddr(t.ctx, addr, tlsConf, &quic.Config{
		EnableDatagrams: true,
		MaxIdleTimeout:  MaxIdleTimeout,
	})
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDialFailed, err)
	}

	conn := t.handleConnection(quicConn)
	if conn == nil {
		return nil, ErrConnFailed
	}
	return conn, nil
}

// GetConnection retrieves an active connection by peer key.
// Returns the connection and whether it was found.
func (t *Transport) GetConnection(peerKey string) (*Conn, bool) {
	t.mu.RLock()
	conn, ok := t.conns[peerKey]
	t.mu.RUnlock()
	return conn, ok
}

// ListConnections returns a slice of all active connections.
func (t *Transport) ListConnections() []*Conn {
	t.mu.RLock()
	defer t.mu.RUnlock()

	conns := make([]*Conn, 0, len(t.conns))
	for _, conn := range t.conns {
		conns = append(conns, conn)
	}
	return conns
}

// acceptLoop continuously accepts incoming connections
func (t *Transport) acceptLoop() {
	defer t.cancel()
	for {
		select {
		case <-t.ctx.Done():
			return
		default:
			conn, err := t.listener.Accept(t.ctx)
			if err != nil {
				// Only log if it's not due to context cancellation/listener closing
				if t.ctx.Err() == nil {
					fmt.Printf("Failed to accept connection: %v\n", err)
				}
				if t.ctx.Err() != nil {
					return
				}
				continue
			}

			go t.handleConnection(conn)
		}
	}
}

// handleConnection processes a new QUIC connection
func (t *Transport) handleConnection(qConn quic.Connection) *Conn {
	peerKey, err := t.config.CertValidator.ExtractPublicKey(qConn.ConnectionState().TLS.PeerCertificates[0])
	if err != nil {
		fmt.Printf("Failed to extract peer key: %v\n", err)
		if cerr := qConn.CloseWithError(0, fmt.Sprintf("%s: %v", ErrInvalidCertificate.Error(), err)); cerr != nil {
			fmt.Printf("Failed to close connection: %v\n", cerr)
		}
		return nil
	}

	conn := t.manageConnection(peerKey, qConn)

	if err := t.config.Handler.OnConnection(conn); err != nil {
		t.cleanup(peerKey)
		if cerr := qConn.CloseWithError(0, err.Error()); cerr != nil {
			fmt.Printf("Failed to close connection: %v\n", cerr)
		}
		return nil
	}

	return conn
}

// manageConnection handles connection storage and replacement
func (t *Transport) manageConnection(peerKey ed25519.PublicKey, qConn quic.Connection) *Conn {
	t.mu.Lock()
	defer t.mu.Unlock()

	// Close existing connection if any
	if existingConn, exists := t.conns[string(peerKey)]; exists {
		fmt.Println("Found existing connection, closing it")
		if err := existingConn.Close(); err != nil {
			fmt.Printf("Failed to close existing connection: %v\n", err)
		}
		delete(t.conns, string(peerKey))
	}

	// Create and store new connection
	conn := newConn(qConn, t)
	conn.peerKey = peerKey
	t.conns[string(peerKey)] = conn

	return conn
}

// Cleanup removes a connection from the map
func (t *Transport) cleanup(peerKey ed25519.PublicKey) {
	t.mu.Lock()
	delete(t.conns, string(peerKey))
	t.mu.Unlock()
}
