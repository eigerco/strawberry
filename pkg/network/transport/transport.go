package transport

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"time"

	"github.com/quic-go/quic-go"
)

// MaxIdleTimeout defines the maximum duration a connection can be idle before timing out
const MaxIdleTimeout = 30 * time.Minute

// CertValidator performs TLS certificate validation and public key extraction
type CertValidator interface {
	// ValidateCertificate checks if a certificate meets required criteria
	ValidateCertificate(cert *x509.Certificate) error
	// ExtractPublicKey retrieves the Ed25519 public key from a certificate
	ExtractPublicKey(cert *x509.Certificate) (ed25519.PublicKey, error)
}

// ConnectionHandler defines how new connections are processed at the protocol level.
// This interface separates transport-level connection handling from protocol-specific
// behaviors.
type ConnectionHandler interface {
	// OnConnection is called after a new connection is established and authenticated.
	// The handler typically sets up protocol-specific streams and state.
	OnConnection(conn *Conn)
	// GetProtocols returns supported ALPN protocol strings
	GetProtocols() []string
	// ValidateConnection verifies TLS parameters including ALPN protocol selection.
	// This is called during the TLS handshake after certificate validation.
	ValidateConnection(tlsState tls.ConnectionState) error
}

// Config holds all parameters needed to initialize a Transport.
// This includes cryptographic keys, network configuration, and handlers.
type Config struct {
	PublicKey     ed25519.PublicKey  // Node's public key
	PrivateKey    ed25519.PrivateKey // Node's private key
	TLSCert       *tls.Certificate   // TLS certificate
	ListenAddr    *net.UDPAddr       // Address to listen on
	CertValidator CertValidator      // Certificate validator
	Handler       ConnectionHandler  // Connection handler
	Context       context.Context    // Context for transport lifecycle
}

// Transport manages the networking layer of a JAMNP-S node.
// It handles:
// - Starting/stopping the QUIC listener
// - Initiating outbound connections
// - TLS handshakes and certificate validation
// - Forwarding authenticated connections to protocol handlers
type Transport struct {
	config   Config
	listener *quic.Listener
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
	ctx, cancel := context.WithCancel(config.Context)
	return &Transport{
		config: config,
		ctx:    ctx,
		cancel: cancel,
	}, nil
}

// Start begins listening for incoming QUIC connections.
// It configures TLS with:
// - Required client certificates
// - TLS 1.3 minimum version
// - JAMNP-S certificate validation
// - ALPN protocol validation
func (t *Transport) Start() error {
	tlsConfig := &tls.Config{
		Certificates:       []tls.Certificate{*t.config.TLSCert},
		NextProtos:         t.config.Handler.GetProtocols(),
		ClientAuth:         tls.RequireAnyClientCert,
		MinVersion:         tls.VersionTLS13,
		InsecureSkipVerify: true, // We do our own certificate validation
		VerifyConnection: func(cs tls.ConnectionState) error {
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

	listener, err := quic.ListenAddr(t.config.ListenAddr.AddrPort().String(), tlsConfig, &quic.Config{
		EnableDatagrams: true,
		MaxIdleTimeout:  MaxIdleTimeout,
	})
	if err != nil {
		return fmt.Errorf("%w: %v", ErrListenerFailed, err)
	}

	t.listener = listener
	t.done = make(chan struct{})
	go func() {
		t.acceptLoop()
		close(t.done)
	}()
	return nil
}

// Connect initiates an outbound connection to a peer.
// The connection follows the same TLS configuration and validation
// as incoming connections.
func (t *Transport) Connect(addr *net.UDPAddr) error {
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

	quicConn, err := quic.DialAddr(t.ctx, addr.AddrPort().String(), tlsConf, &quic.Config{
		EnableDatagrams: true,
		MaxIdleTimeout:  MaxIdleTimeout,
	})
	if err != nil {
		return fmt.Errorf("%w: %v", ErrDialFailed, err)
	}

	t.handleConnection(quicConn)
	return nil
}

// Stop gracefully shuts down the transport and all active connections.
// Waits for the accept loop to finish before returning.
func (t *Transport) Stop() error {
	// Only call cancel if it wasn't already cancelled by parent
	select {
	case <-t.ctx.Done():
		// Context was already cancelled by parent
	default:
		t.cancel()
	}
	if t.listener != nil {
		if err := t.listener.Close(); err != nil {
			return fmt.Errorf("failed to close listener: %w", err)
		}
	}
	<-t.done
	return nil
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

// handleConnection processes a new QUIC connection after acceptance/dialing.
// It:
// 1. Extracts the peer's Ed25519 key from their certificate
// 2. Creates a Conn wrapper around the QUIC connection
// 3. Passes the connection to the protocol handler
func (t *Transport) handleConnection(qConn quic.Connection) {
	peerKey, err := t.config.CertValidator.ExtractPublicKey(qConn.ConnectionState().TLS.PeerCertificates[0])
	if err != nil {
		fmt.Printf("Failed to extract peer key: %v\n", err)
		if cerr := qConn.CloseWithError(0, fmt.Sprintf("%s: %v", ErrInvalidCertificate.Error(), err)); cerr != nil {
			fmt.Printf("Failed to close connection: %v\n", cerr)
		}
	}

	conn := newConn(qConn, t)
	conn.SetPeerKey(peerKey)
	t.config.Handler.OnConnection(conn)
}
