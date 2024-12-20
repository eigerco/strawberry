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

const MaxIdleTimeout = 30 * time.Minute

type StreamHandler interface {
	HandleStream(ctx context.Context, stream quic.Stream) error
}

type StreamRegistry interface {
	// Takes a raw byte instead of a StreamKind
	GetHandler(kindByte byte) (StreamHandler, error)
	ValidateKind(kindByte byte) error
}

// CertValidator validates certificates and extracts public keys
type CertValidator interface {
	ValidateCertificate(cert *x509.Certificate) error
	ExtractPublicKey(cert *x509.Certificate) (ed25519.PublicKey, error)
}

// ProtocolManager handles ALPN protocol identification
type ProtocolManager interface {
	// AcceptableProtocols returns the set of acceptable protocol strings for a chain
	AcceptableProtocols(chainHash string) []string

	// NewProtocolID creates a protocol identifier string
	NewProtocolID(chainHash string, isBuilder bool) string

	// ValidateProtocol validates a protocol string
	ValidateProtocol(protocol string) error
}

type ConnectionHandler interface {
	OnConnection(conn *Conn) error
	GetProtocols() []string
	ValidateConnection(tlsState tls.ConnectionState) error
}

type Config struct {
	PublicKey     ed25519.PublicKey
	PrivateKey    ed25519.PrivateKey
	TLSCert       *tls.Certificate
	ListenAddr    string
	CertValidator CertValidator
	Handler       ConnectionHandler
}

// Transport manages QUIC connections and streams
type Transport struct {
	config Config

	listener *quic.Listener

	mu    sync.RWMutex
	conns map[string]*Conn

	ctx    context.Context
	cancel context.CancelFunc
}

// NewTransport creates a new QUIC transport
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

	ctx, cancel := context.WithCancel(context.Background())

	return &Transport{
		config: config,
		conns:  make(map[string]*Conn),
		ctx:    ctx,
		cancel: cancel,
	}, nil
}

// Start starts the transport listener
func (t *Transport) Start() error {
	tlsConfig := &tls.Config{
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
			return t.config.CertValidator.ValidateCertificate(c)
		},
	}

	listener, err := quic.ListenAddr(t.config.ListenAddr, tlsConfig, &quic.Config{
		EnableDatagrams: true,
		MaxIdleTimeout:  MaxIdleTimeout,
	})
	if err != nil {
		return fmt.Errorf("%w: %v", ErrListenerFailed, err)
	}

	t.listener = listener
	go t.acceptLoop()
	return nil
}

// Stop stops the transport
func (t *Transport) Stop() error {
	t.cancel()
	if t.listener != nil {
		return t.listener.Close()
	}
	return nil
}

// acceptLoop accepts incoming QUIC connections
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

// Connect initiates a connection to a peer
func (t *Transport) Connect(addr string) (*Conn, error) {
	t.mu.RLock()
	for _, existingConn := range t.conns {
		asd := existingConn.qConn.RemoteAddr().String()
		if asd == addr {
			// Check if connection is still active
			select {
			case <-existingConn.qConn.Context().Done():
				// Connection is closed, remove it
				t.mu.RUnlock()
				t.cleanup(existingConn.peerKey)
			default:
				// Connection is still active
				t.mu.RUnlock()
				return existingConn, nil
			}
		}
	}
	t.mu.RUnlock()
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

func (t *Transport) handleConnection(qConn quic.Connection) *Conn {
	tlsState := qConn.ConnectionState().TLS

	if err := t.verifyPeerCert(tlsState.PeerCertificates); err != nil {
		if cerr := qConn.CloseWithError(0, ErrInvalidCertificate.Error()); cerr != nil {
			fmt.Printf("Failed to close connection: %v\n", cerr)
		}
		return nil
	}

	if err := t.config.Handler.ValidateConnection(tlsState); err != nil {
		fmt.Printf("Failed to validate connection: %v\n", err)
		if cerr := qConn.CloseWithError(0, err.Error()); cerr != nil {
			fmt.Printf("Failed to close connection: %v\n", cerr)
		}
		return nil
	}

	peerKey, err := t.config.CertValidator.ExtractPublicKey(tlsState.PeerCertificates[0])
	if err != nil {
		fmt.Printf("Failed to extract peer key: %v\n", err)
		if cerr := qConn.CloseWithError(0, fmt.Sprintf("%s: %v", ErrInvalidCertificate.Error(), err)); cerr != nil {
			fmt.Printf("Failed to close connection: %v\n", cerr)
		}
		return nil
	}

	t.mu.RLock()
	_, exists := t.conns[string(peerKey)]
	t.mu.RUnlock()
	if exists {
		fmt.Println("Connection already exists")
		if cerr := qConn.CloseWithError(0, ErrConnectionExists.Error()); cerr != nil {
			fmt.Printf("Failed to close connection: %v\n", cerr)
		}
		return nil
	}

	conn := newConn(qConn, t)
	conn.peerKey = peerKey

	// Store connection
	t.mu.Lock()
	t.conns[string(peerKey)] = conn
	t.mu.Unlock()

	if err := t.config.Handler.OnConnection(conn); err != nil {
		t.cleanup(peerKey)
		if cerr := qConn.CloseWithError(0, err.Error()); cerr != nil {
			fmt.Printf("Failed to close connection: %v\n", cerr)
		}
		return nil
	}

	return conn
}

// GetConnection returns a connection by peer key if it exists
func (t *Transport) GetConnection(peerKey string) (*Conn, bool) {
	t.mu.RLock()
	conn, ok := t.conns[peerKey]
	t.mu.RUnlock()
	return conn, ok
}

// ListConnections returns all active connections
func (t *Transport) ListConnections() []*Conn {
	t.mu.RLock()
	defer t.mu.RUnlock()

	conns := make([]*Conn, 0, len(t.conns))
	for _, conn := range t.conns {
		conns = append(conns, conn)
	}
	return conns
}

// Cleanup removes a connection from the map
func (t *Transport) cleanup(peerKey ed25519.PublicKey) {
	t.mu.Lock()
	delete(t.conns, string(peerKey))
	t.mu.Unlock()
}

// verifyPeerCert verifies the peer's certificate chain
func (t *Transport) verifyPeerCert(certs []*x509.Certificate) error {
	if len(certs) == 0 {
		return fmt.Errorf("%w: no certificates provided", ErrInvalidCertificate)
	}
	if err := t.config.CertValidator.ValidateCertificate(certs[0]); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidCertificate, err)
	}

	return nil
}
