package cert

import (
	"crypto/ed25519"
	"crypto/rand"
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

type Config struct {
	PublicKey          ed25519.PublicKey
	PrivateKey         ed25519.PrivateKey
	CertValidityPeriod time.Duration
}

type Generator struct {
	config Config
}

func NewGenerator(config Config) *Generator {
	return &Generator{config: config}
}

func encodePubKeyToDNS(pubKey ed25519.PublicKey) string {
	return DNSNamePrefix + base32Encoding.EncodeToString(pubKey)
}

func (g *Generator) GenerateCertificate() (*x509.Certificate, error) {
	dnsName := encodePubKeyToDNS(g.config.PublicKey)

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

	return cert, nil
}

func ValidateCertificate(cert *x509.Certificate) error {
	// Check signature algorithm
	if cert.SignatureAlgorithm != x509.PureEd25519 {
		return fmt.Errorf("invalid signature algorithm: expected Ed25519")
	}

	// Check DNS names
	if len(cert.DNSNames) != 1 {
		return fmt.Errorf("certificate must have exactly one DNS name")
	}
	dnsName := cert.DNSNames[0]

	// Verify format
	if len(dnsName) != 53 || !strings.HasPrefix(dnsName, DNSNamePrefix) {
		return fmt.Errorf("invalid DNS name format: %s", dnsName)
	}

	// Validate public key
	pubKey, ok := cert.PublicKey.(ed25519.PublicKey)
	if !ok {
		return fmt.Errorf("certificate public key is not an Ed25519 key")
	}
	expectedDNSName := encodePubKeyToDNS(pubKey)
	if dnsName != expectedDNSName {
		return fmt.Errorf("DNS name does not match public key: got %s, expected %s", dnsName, expectedDNSName)
	}

	// Check expiration
	now := time.Now()
	if now.Before(cert.NotBefore) {
		return fmt.Errorf("certificate is not yet valid: valid from %v", cert.NotBefore)
	}
	if now.After(cert.NotAfter) {
		return fmt.Errorf("certificate has expired: valid until %v", cert.NotAfter)
	}

	return nil
}
