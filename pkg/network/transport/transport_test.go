package transport

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/eigerco/strawberry/pkg/network/mocks"
	"github.com/eigerco/strawberry/pkg/network/mocks/quicconn"
	"github.com/quic-go/quic-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

type MockQuicListener struct {
	mock.Mock
}

func (m *MockQuicListener) Accept(ctx context.Context) (quic.Connection, error) {
	args := m.Called(ctx)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(quic.Connection), args.Error(1)
}

func (m *MockQuicListener) Addr() net.Addr {
	args := m.Called()
	return args.Get(0).(net.Addr)
}

func (m *MockQuicListener) Close() error {
	args := m.Called()
	return args.Error(0)
}

type MockQuicDialer struct {
	mock.Mock
}

func NewMockQuicDialer() *MockQuicDialer {
	return new(MockQuicDialer)
}

func (m *MockQuicDialer) DialAddr(ctx context.Context, addr string, tlsConf *tls.Config, quicConfig *quic.Config) (quic.Connection, error) {
	args := m.Called(ctx, addr, tlsConf, quicConfig)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(quic.Connection), args.Error(1)
}

type MockCertValidator struct {
	mock.Mock
}

func NewMockCertValidator() *MockCertValidator {
	return new(MockCertValidator)
}

func (m *MockCertValidator) ValidateCertificate(cert *x509.Certificate) error {
	args := m.Called(cert)
	return args.Error(0)
}

func (m *MockCertValidator) ExtractPublicKey(cert *x509.Certificate) (ed25519.PublicKey, error) {
	args := m.Called(cert)
	return args.Get(0).(ed25519.PublicKey), args.Error(1)
}

type MockConnectionHandler struct {
	mock.Mock
}

func NewMockConnectionHandler() *MockConnectionHandler {
	return new(MockConnectionHandler)
}

func (m *MockConnectionHandler) OnConnection(conn *Conn) {
	m.Called(conn)
}
func (m *MockConnectionHandler) GetProtocols() []string {
	args := m.Called()
	return args.Get(0).([]string)
}
func (m *MockConnectionHandler) ValidateConnection(tlsState tls.ConnectionState) error {
	args := m.Called(tlsState)
	return args.Error(0)
}
func generateTestCredentials(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey, *tls.Certificate) {
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "test.example.com",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, pubKey, privKey)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)
	tlsCert := &tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  privKey,
		Leaf:        cert,
	}

	return pubKey, privKey, tlsCert
}

func TestConnect(t *testing.T) {
	pubKey, privKey, tlsCert := generateTestCredentials(t)
	peerPubKey, _, peerTLSCert := generateTestCredentials(t)

	testAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1234}
	testAddrString := testAddr.AddrPort().String()

	tests := []struct {
		name          string
		setupMocks    func(mockDialer *MockQuicDialer, mockValidator *MockCertValidator, mockHandler *MockConnectionHandler)
		validateMocks func(t *testing.T, mockDialer *MockQuicDialer)
		expectedError error
	}{
		{
			name: "Successful connection",
			setupMocks: func(mockDialer *MockQuicDialer, mockValidator *MockCertValidator, mockHandler *MockConnectionHandler) {
				mockQConn := mocks.NewMockQuicConnection()
				connState := quic.ConnectionState{
					TLS: tls.ConnectionState{
						PeerCertificates: []*x509.Certificate{peerTLSCert.Leaf},
					},
				}
				mockQConn.On("ConnectionState").Return(connState)
				mockQConn.On("Context").Return(context.Background())

				// Mock the DialAddr call - this happens in Connect
				mockDialer.On(
					"DialAddr",
					mock.Anything,
					testAddrString,
					mock.MatchedBy(func(config *tls.Config) bool {
						return len(config.NextProtos) > 0 &&
							config.MinVersion == tls.VersionTLS13 &&
							config.ClientAuth == tls.RequireAnyClientCert
					}),
					mock.MatchedBy(func(config *quic.Config) bool {
						return config.EnableDatagrams == true &&
							config.MaxIdleTimeout == MaxIdleTimeout
					}),
				).Return(mockQConn, nil)

				mockValidator.On("ExtractPublicKey", peerTLSCert.Leaf).Return(peerPubKey, nil)
				mockHandler.On("OnConnection", mock.MatchedBy(func(conn *Conn) bool {
					if conn == nil {
						t.Logf("MATCH FAILED: Connection is nil")
						return false
					}

					// Check peer key matches
					if !(conn.PeerKey().Equal(peerPubKey)) {
						t.Logf("MATCH FAILED: Peer key mismatch. Got %v, expected %v",
							conn.PeerKey(), peerPubKey)
						return false
					}

					// Check QUIC connection is the expected mock
					if conn.QConn() != mockQConn {
						t.Logf("MATCH FAILED: QUIC connection mismatch. Got %v, expected %v",
							conn.QConn(), mockQConn)
						return false
					}

					// Check transport is set
					if conn.transport == nil {
						t.Logf("MATCH FAILED: Transport is nil")
						return false
					}

					return true
				})).Return()

				// This is needed for certificate validation in Transport.Connect
				mockValidator.On("ValidateCertificate", mock.AnythingOfType("*x509.Certificate")).Return(nil)
			},
			validateMocks: func(t *testing.T, mockDialer *MockQuicDialer) {
				mockDialer.AssertCalled(t, "DialAddr",
					mock.Anything,
					testAddrString,
					mock.Anything,
					mock.Anything)
			},
			expectedError: nil,
		},
		{
			name: "Dial failure",
			setupMocks: func(mockDialer *MockQuicDialer, mockValidator *MockCertValidator, mockHandler *MockConnectionHandler) {
				// Simulate dial failure
				mockDialer.On(
					"DialAddr",
					mock.Anything,
					testAddrString,
					mock.Anything,
					mock.Anything,
				).Return(nil, errors.New("dial failed"))

				// This is for the initial validation in NewTransport
				mockValidator.On("ValidateCertificate", mock.AnythingOfType("*x509.Certificate")).Return(nil)
			},
			validateMocks: func(t *testing.T, mockDialer *MockQuicDialer) {
				mockDialer.AssertCalled(t, "DialAddr",
					mock.Anything,
					testAddrString,
					mock.Anything,
					mock.Anything)
			},
			expectedError: ErrDialFailed,
		},
		{
			name: "Certificate validation failure",
			setupMocks: func(mockDialer *MockQuicDialer, mockValidator *MockCertValidator, mockHandler *MockConnectionHandler) {
				mockValidator.On("ValidateCertificate", tlsCert.Leaf).Return(nil)

				// Set up the dialer to fail with certificate validation error
				mockDialer.On(
					"DialAddr",
					mock.Anything,
					testAddrString,
					mock.MatchedBy(func(config *tls.Config) bool {
						// Extract the VerifyPeerCertificate function and call it
						// with a certificate that will fail validation
						if config.VerifyPeerCertificate != nil {
							// Simulate certificate parsing failure
							rawCerts := [][]byte{[]byte("invalid cert")}
							err := config.VerifyPeerCertificate(rawCerts, nil)
							// We expect this to fail
							return err != nil
						}
						return false
					}),
					mock.Anything,
				).Return(nil, ErrInvalidCertificate)
			},
			validateMocks: func(t *testing.T, mockDialer *MockQuicDialer) {
				mockDialer.AssertCalled(t, "DialAddr",
					mock.Anything,
					testAddrString,
					mock.Anything,
					mock.Anything)
			},
			expectedError: ErrInvalidCertificate,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockValidator := NewMockCertValidator()
			mockHandler := NewMockConnectionHandler()
			mockDialer := NewMockQuicDialer()

			mockHandler.On("GetProtocols").Return([]string{"test-protocol"})

			tt.setupMocks(mockDialer, mockValidator, mockHandler)

			config := Config{
				PublicKey:     pubKey,
				PrivateKey:    privKey,
				TLSCert:       tlsCert,
				ListenAddr:    &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0},
				CertValidator: mockValidator,
				Handler:       mockHandler,
				Context:       context.Background(),
			}

			transport, err := NewTransport(config)
			require.NoError(t, err)
			require.NotNil(t, transport)

			transport.SetDialer(mockDialer)

			// Execute
			err = transport.Connect(testAddr)

			if tt.expectedError != nil {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError.Error())
			} else {
				assert.NoError(t, err)
			}

			// Validate that mocks were called correctly
			tt.validateMocks(t, mockDialer)
			mockDialer.AssertExpectations(t)
			mockValidator.AssertExpectations(t)
		})
	}
}

func TestHandleConnection(t *testing.T) {
	pubKey, privKey, tlsCert := generateTestCredentials(t)
	peerPubKey, _, peerTLSCert := generateTestCredentials(t)
	testAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 2345}

	tests := []struct {
		name          string
		setupMocks    func(mockQConn *quicconn.MockQuicConnection, mockValidator *MockCertValidator, mockHandler *MockConnectionHandler)
		validateMocks func(t *testing.T, mockQConn *quicconn.MockQuicConnection, mockHandler *MockConnectionHandler)
		expectError   bool
	}{
		{
			name: "Successful connection handling",
			setupMocks: func(mockQConn *quicconn.MockQuicConnection, mockValidator *MockCertValidator, mockHandler *MockConnectionHandler) {
				connState := quic.ConnectionState{
					TLS: tls.ConnectionState{
						PeerCertificates: []*x509.Certificate{peerTLSCert.Leaf},
					},
				}
				mockQConn.On("Context").Return(context.Background())
				mockQConn.On("ConnectionState").Return(connState)
				mockValidator.On("ExtractPublicKey", peerTLSCert.Leaf).Return(peerPubKey, nil)
				mockHandler.On("OnConnection", mock.MatchedBy(func(conn *Conn) bool {
					return conn != nil &&
						conn.PeerKey().Equal(peerPubKey) &&
						conn.QConn() == mockQConn
				})).Return()
			},
			validateMocks: func(t *testing.T, mockQConn *quicconn.MockQuicConnection, mockHandler *MockConnectionHandler) {
				mockQConn.AssertCalled(t, "ConnectionState")
				mockQConn.AssertCalled(t, "Context")
				mockHandler.AssertCalled(t, "OnConnection", mock.Anything)
			},
			expectError: false,
		},
		{
			name: "Extract public key error",
			setupMocks: func(mockQConn *quicconn.MockQuicConnection, mockValidator *MockCertValidator, mockHandler *MockConnectionHandler) {
				connState := quic.ConnectionState{
					TLS: tls.ConnectionState{
						PeerCertificates: []*x509.Certificate{peerTLSCert.Leaf},
					},
				}
				mockQConn.On("ConnectionState").Return(connState)

				// For closing the connection when key extraction fails
				mockQConn.On("CloseWithError", mock.Anything, mock.Anything).Return(nil)

				// Simulate failure to extract public key
				mockValidator.On("ExtractPublicKey", peerTLSCert.Leaf).Return(
					ed25519.PublicKey{}, errors.New("failed to extract key"))
			},
			validateMocks: func(t *testing.T, mockQConn *quicconn.MockQuicConnection, mockHandler *MockConnectionHandler) {
				mockQConn.AssertCalled(t, "ConnectionState")
				mockQConn.AssertCalled(t, "CloseWithError", mock.Anything, mock.Anything)
				mockHandler.AssertNotCalled(t, "OnConnection", mock.Anything)
				mockHandler.AssertNotCalled(t, "Context", mock.Anything)
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockValidator := NewMockCertValidator()
			mockHandler := NewMockConnectionHandler()
			mockQConn := mocks.NewMockQuicConnection()

			// Add expectation for ValidateCertificate which is called in NewTransport
			mockValidator.On("ValidateCertificate", mock.AnythingOfType("*x509.Certificate")).Return(nil)

			tt.setupMocks(mockQConn, mockValidator, mockHandler)

			config := Config{
				PublicKey:     pubKey,
				PrivateKey:    privKey,
				TLSCert:       tlsCert,
				ListenAddr:    testAddr,
				CertValidator: mockValidator,
				Handler:       mockHandler,
				Context:       context.Background(),
			}

			transport, err := NewTransport(config)
			require.NoError(t, err)
			require.NotNil(t, transport)

			// If this is a "successful" test case, we expect OnConnection to be called
			if tt.name == "Successful connection handling" {
				mockHandler.On("OnConnection", mock.Anything).Return()
			}

			// Execute
			transport.handleConnection(mockQConn)

			// Validate that mocks were called correctly
			tt.validateMocks(t, mockQConn, mockHandler)
			mockQConn.AssertExpectations(t)
			mockValidator.AssertExpectations(t)
			mockHandler.AssertExpectations(t)
		})
	}
}
