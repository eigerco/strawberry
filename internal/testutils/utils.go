package testutils

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/stretchr/testify/require"
)

func RandomHash(t *testing.T) crypto.Hash {
	hash := make([]byte, crypto.HashSize)
	_, err := rand.Read(hash)
	require.NoError(t, err)
	return crypto.Hash(hash)
}

func RandomED25519PublicKey(t *testing.T) crypto.Ed25519PublicKey {
	hash := make([]byte, ed25519.PublicKeySize)
	_, err := rand.Read(hash)
	require.NoError(t, err)
	return hash
}
func RandomBandersnatchPublicKey(t *testing.T) crypto.BandersnatchPublicKey {
	hash := make([]byte, crypto.BandersnatchSize)
	_, err := rand.Read(hash)
	require.NoError(t, err)
	return crypto.BandersnatchPublicKey(hash)
}

func RandomBandersnatchSignature(t *testing.T) crypto.BandersnatchSignature {
	hash := make([]byte, 96)
	_, err := rand.Read(hash)
	require.NoError(t, err)
	return crypto.BandersnatchSignature(hash)
}

func RandomEd25519Signature(t *testing.T) [crypto.Ed25519SignatureSize]byte {
	var hash [crypto.Ed25519SignatureSize]byte
	_, err := rand.Read(hash[:])
	require.NoError(t, err)
	return hash
}

func RandomTicketProof(t *testing.T) [784]byte {
	var hash [784]byte
	_, err := rand.Read(hash[:])
	require.NoError(t, err)
	return hash
}
