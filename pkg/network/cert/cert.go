package cert

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base32"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/eigerco/strawberry/internal/crypto/ed25519"
)

// DNSNamePrefix is prepended to all encoded public keys in certificate DNS names
const (
	DNSNamePrefix = "e"
)

// base32Encoding defines the custom base32 alphabet used for encoding public keys
var base32Encoding = base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").WithPadding(base32.NoPadding)

// Generator creates TLS certificates with Ed25519 keys and encoded DNS names.
type Generator struct {
	config Config
}

// Config contains the parameters needed for certificate generation.
type Config struct {
	// PublicKey is the Ed25519 public key to embed in the certificate
	PublicKey ed25519.PublicKey
	// PrivateKey is used to sign the certificate
	PrivateKey ed25519.PrivateKey
	// CertValidityPeriod defines how long the certificate remains valid
	CertValidityPeriod time.Duration
}

// NewGenerator creates a new certificate generator with the given configuration.
func NewGenerator(config Config) *Generator {
	return &Generator{config: config}
}

// Validator checks certificates for compliance with protocol requirements.
// Implements the transport.CertValidator interface.
type Validator struct{}

// NewValidator creates a new certificate validator.
func NewValidator() *Validator {
	return &Validator{}
}

// ValidateCertificate checks if a certificate meets the protocol requirements:
// - Uses Ed25519 for signatures
// - Contains exactly one DNS name
// - DNS name matches encoded public key format
// - Certificate is within its validity period
func (v *Validator) ValidateCertificate(cert *x509.Certificate) error {
	if cert.SignatureAlgorithm != x509.PureEd25519 {
		return fmt.Errorf("invalid signature algorithm: expected Ed25519")
	}

	pubKey, ok := cert.PublicKey.(ed25519.PublicKey)
	if !ok {
		return fmt.Errorf("certificate public key is not Ed25519")
	}

	if len(cert.DNSNames) != 1 {
		return fmt.Errorf("certificate must have exactly one DNS name")
	}
	dnsName := cert.DNSNames[0]

	if len(dnsName) != 53 || !strings.HasPrefix(dnsName, DNSNamePrefix) {
		return fmt.Errorf("invalid DNS name format: %s (length: %d)", dnsName, len(dnsName))
	}

	// Generate expected DNS name
	expectedDNSName := EncodePubKeyToDNS(pubKey)

	if dnsName != expectedDNSName {
		return fmt.Errorf("DNS name does not match public key")
	}

	// Check expiration
	now := time.Now()
	if now.Before(cert.NotBefore) {
		return fmt.Errorf("certificate is not yet valid")
	}
	if now.After(cert.NotAfter) {
		return fmt.Errorf("certificate has expired")
	}
	return nil
}

// ExtractPublicKey retrieves the Ed25519 public key from a certificate.
// Returns an error if the certificate doesn't use an Ed25519 key.
func (v *Validator) ExtractPublicKey(cert *x509.Certificate) (ed25519.PublicKey, error) {
	pubKey, ok := cert.PublicKey.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("certificate public key is not an Ed25519 key")
	}
	return pubKey, nil
}

// EncodePubKeyToDNS encodes an Ed25519 public key into a DNS name.
// The format is: "e" + base32(pubKey) with custom alphabet.
func EncodePubKeyToDNS(pubKey ed25519.PublicKey) string {
	return DNSNamePrefix + base32Encoding.EncodeToString(pubKey)
}

// GenerateCertificate creates a new self-signed TLS certificate.
// The certificate:
// - Uses Ed25519 for key and signature
// - Includes the encoded public key as DNS name
// - Is valid for the configured duration
// - Supports both server and client authentication
func (g *Generator) GenerateCertificate() (*tls.Certificate, error) {
	dnsName := EncodePubKeyToDNS(g.config.PublicKey)

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: dnsName,
		},
		DNSNames:  []string{dnsName},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(g.config.CertValidityPeriod),
		KeyUsage:  x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
			x509.ExtKeyUsageClientAuth,
		},
		SignatureAlgorithm:    x509.PureEd25519,
		PublicKeyAlgorithm:    x509.Ed25519,
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, g.config.PublicKey, g.config.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	return &tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  g.config.PrivateKey,
		Leaf:        cert,
	}, nil
}
