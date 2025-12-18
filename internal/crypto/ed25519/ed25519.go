// Package ed25519 provides a drop-in replacement for crypto/ed25519
// with ZIP-215 compliant signature verification.
package ed25519

import (
	"bytes"
	"io"

	"crypto/ed25519"

	"github.com/hdevalence/ed25519consensus"
)

type (
	PublicKey  = ed25519.PublicKey
	PrivateKey = ed25519.PrivateKey
)

const (
	PublicKeySize  = ed25519.PublicKeySize
	PrivateKeySize = ed25519.PrivateKeySize
	SignatureSize  = ed25519.SignatureSize
	SeedSize       = ed25519.SeedSize
)

// GenerateKey uses the standard library's key generation.
func GenerateKey(rand io.Reader) (PublicKey, PrivateKey, error) {
	return ed25519.GenerateKey(rand)
}

// NewKeyFromSeed uses the standard library's function.
func NewKeyFromSeed(seed []byte) PrivateKey {
	return ed25519.NewKeyFromSeed(seed)
}

// Sign uses the standard library's signing function.
func Sign(privateKey PrivateKey, message []byte) []byte {
	return ed25519.Sign(privateKey, message)
}

// Verify uses the hdevalence/ed25519consensus library for
// ZIP-215 compliant verification.
func Verify(publicKey PublicKey, message, sig []byte) bool {
	return ed25519consensus.Verify(publicKey, message, sig)
}

// ZeroPublicKey is pre-allocated to avoid allocations in IsEmpty.
var ZeroPublicKey = make([]byte, PublicKeySize)

// IsEmpty checks if the given public key is empty or all zeros.
func IsEmpty(pk PublicKey) bool {
	return len(pk) == 0 || bytes.Equal(pk, ZeroPublicKey)
}
