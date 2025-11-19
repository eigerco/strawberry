package cert

import (
	"crypto/x509"
	"testing"
	"time"

	"github.com/eigerco/strawberry/internal/crypto/ed25519"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateCertificateSuccess(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err, "Failed to generate Ed25519 key pair")

	config := Config{
		PublicKey:          pub,
		PrivateKey:         priv,
		CertValidityPeriod: 24 * time.Hour,
	}

	generator := NewGenerator(config)
	cert, err := generator.GenerateCertificate()

	require.NoError(t, err, "Failed to generate certificate")
	assert.NotNil(t, cert, "Generated certificate should not be nil")
}

func TestValidateCertificateSuccess(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err, "Failed to generate Ed25519 key pair")

	config := Config{
		PublicKey:          pub,
		PrivateKey:         priv,
		CertValidityPeriod: 24 * time.Hour,
	}
	generator := NewGenerator(config)
	cert, err := generator.GenerateCertificate()
	require.NoError(t, err, "Failed to generate certificate")

	err = NewValidator().ValidateCertificate(cert.Leaf)
	assert.NoError(t, err, "Valid certificate failed validation")
}

func TestValidateCertificateFailsForMismatchedPublicKey(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err, "Failed to generate Ed25519 key pair")

	config := Config{
		PublicKey:          pub,
		PrivateKey:         priv,
		CertValidityPeriod: 24 * time.Hour,
	}
	generator := NewGenerator(config)
	cert, err := generator.GenerateCertificate()
	require.NoError(t, err, "Failed to generate certificate")

	// Tamper with the public key
	wrongPub, _, err := ed25519.GenerateKey(nil)
	require.NoError(t, err, "Failed to generate a new Ed25519 key pair")
	cert.Leaf.PublicKey = wrongPub

	err = NewValidator().ValidateCertificate(cert.Leaf)
	assert.Error(t, err, "Expected validation to fail for certificate with mismatched DNS name and public key")
}

func TestCertificateDNSNameFormat(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err, "Failed to generate Ed25519 key pair")

	config := Config{
		PublicKey:          pub,
		PrivateKey:         priv,
		CertValidityPeriod: 24 * time.Hour,
	}
	generator := NewGenerator(config)
	cert, err := generator.GenerateCertificate()
	require.NoError(t, err, "Failed to generate certificate")

	require.Len(t, cert.Leaf.DNSNames, 1, "Certificate must have exactly one DNS name")
	dnsName := cert.Leaf.DNSNames[0]
	assert.Equal(t, 53, len(dnsName), "DNS name should be 53 characters long")
	assert.True(t, dnsName[0] == 'e', "DNS name should start with 'e'")
}

func TestCertificateParseDER(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err, "Failed to generate Ed25519 key pair")

	config := Config{
		PublicKey:          pub,
		PrivateKey:         priv,
		CertValidityPeriod: 24 * time.Hour,
	}
	generator := NewGenerator(config)
	cert, err := generator.GenerateCertificate()
	require.NoError(t, err, "Failed to generate certificate")

	parsedCert, err := x509.ParseCertificate(cert.Leaf.Raw)
	assert.NoError(t, err, "Failed to parse generated certificate DER")
	assert.NotNil(t, parsedCert, "Parsed certificate should not be nil")
}

func TestValidateCertificateExpired(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err, "Failed to generate Ed25519 key pair")

	// Create a certificate with a validity period in the past
	config := Config{
		PublicKey:          pub,
		PrivateKey:         priv,
		CertValidityPeriod: -1 * time.Hour, // Expired 1 hour ago
	}
	generator := NewGenerator(config)
	cert, err := generator.GenerateCertificate()
	require.NoError(t, err, "Failed to generate expired certificate")

	// Validate the certificate
	err = NewValidator().ValidateCertificate(cert.Leaf)
	assert.Error(t, err, "Expected validation to fail for expired certificate")
	assert.Contains(t, err.Error(), "certificate has expired", "Expected error message for expired certificate")
}

func TestValidateCertificateFutureStartDate(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err, "Failed to generate Ed25519 key pair")

	// Create a certificate with a validity period starting in the future
	config := Config{
		PublicKey:          pub,
		PrivateKey:         priv,
		CertValidityPeriod: 24 * time.Hour, // Validity starts tomorrow
	}
	generator := NewGenerator(config)
	cert, err := generator.GenerateCertificate()
	require.NoError(t, err, "Failed to generate future-dated certificate")
	cert.Leaf.NotBefore = time.Now().Add(1 * time.Hour) // Adjust NotBefore to 1 hour from now

	// Validate the certificate
	err = NewValidator().ValidateCertificate(cert.Leaf)
	assert.Error(t, err, "Expected validation to fail for not-yet-valid certificate")
	assert.Contains(t, err.Error(), "certificate is not yet valid", "Expected error message for future-dated certificate")
}
