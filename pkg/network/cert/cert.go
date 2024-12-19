package cert

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base32"
	"fmt"
	"math/big"
	"strings"
	"time"
)

const (
	DNSNamePrefix = "e"
)

var base32Encoding = base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").WithPadding(base32.NoPadding)

// Generator handles certificate generation
type Generator struct {
	config Config
}

type Config struct {
	PublicKey          ed25519.PublicKey
	PrivateKey         ed25519.PrivateKey
	CertValidityPeriod time.Duration
}

func NewGenerator(config Config) *Generator {
	return &Generator{config: config}
}

// Validator implements the transport.CertValidator interface
type Validator struct{}

func NewValidator() *Validator {
	return &Validator{}
}

// ValidateCertificate implements transport.CertValidator
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

// ExtractPublicKey implements transport.CertValidator
func (v *Validator) ExtractPublicKey(cert *x509.Certificate) (ed25519.PublicKey, error) {
	pubKey, ok := cert.PublicKey.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("certificate public key is not an Ed25519 key")
	}
	return pubKey, nil
}

// Helper functions used by both Generator and Validator
func EncodePubKeyToDNS(pubKey ed25519.PublicKey) string {
	return DNSNamePrefix + base32Encoding.EncodeToString(pubKey)
}

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
