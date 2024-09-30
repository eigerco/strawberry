package testutils

import (
	"crypto/rand"
	"github.com/eigerco/strawberry/internal/jamtime"
	"testing"

	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/crypto/bandersnatch"
	"github.com/stretchr/testify/require"
)

func RandomHash(t *testing.T) crypto.Hash {
	hash := make([]byte, crypto.HashSize)
	_, err := rand.Read(hash)
	require.NoError(t, err)
	return crypto.Hash(hash)
}

func RandomED25519PublicKey(t *testing.T) crypto.Ed25519PublicKey {
	hash := make([]byte, crypto.Ed25519PublicSize)
	_, err := rand.Read(hash)
	require.NoError(t, err)
	return crypto.Ed25519PublicKey{PublicKey: hash}
}
func RandomBandersnatchPublicKey(t *testing.T) crypto.BandersnatchPublicKey {
	hash := make([]byte, crypto.BandersnatchSerializedSize)
	_, err := rand.Read(hash)
	require.NoError(t, err)
	return crypto.BandersnatchPublicKey(hash)
}

func RandomBandersnatchPrivateKey(t *testing.T) *bandersnatch.PrivateKey {
	hash := make([]byte, crypto.BandersnatchSize)
	_, err := rand.Read(hash)
	require.NoError(t, err)
	key, err := bandersnatch.NewPrivateKeyFromSeed(crypto.BandersnatchSeedKey(hash))
	require.NoError(t, err)
	return key
}

func RandomBlsKey(t *testing.T) crypto.BlsKey {
	hash := make([]byte, crypto.BLSSize)
	_, err := rand.Read(hash)
	require.NoError(t, err)
	return crypto.BlsKey(hash)
}

func RandomMetadataKey(t *testing.T) crypto.MetadataKey {
	hash := make([]byte, crypto.MetadataSize)
	_, err := rand.Read(hash)
	require.NoError(t, err)
	return crypto.MetadataKey(hash)
}

func RandomValidatorKey(t *testing.T) crypto.ValidatorKey {
	return crypto.ValidatorKey{
		Bandersnatch: RandomBandersnatchPublicKey(t),
		Ed25519:      RandomED25519PublicKey(t),
		Bls:          RandomBlsKey(t),
		Metadata:     RandomMetadataKey(t),
	}
}

func RandomBandersnatchSignature(t *testing.T) crypto.BandersnatchSignature {
	hash := make([]byte, 96)
	_, err := rand.Read(hash)
	require.NoError(t, err)
	return crypto.BandersnatchSignature(hash)
}

func RandomBandersnatchRingCommitment(t *testing.T) crypto.RingCommitment {
	hash := make([]byte, crypto.BandersnatchRingSize)
	_, err := rand.Read(hash)
	require.NoError(t, err)
	return crypto.RingCommitment(hash)
}

func RandomEd25519Signature(t *testing.T) [crypto.Ed25519SignatureSize]byte {
	var hash [crypto.Ed25519SignatureSize]byte
	_, err := rand.Read(hash[:])
	require.NoError(t, err)
	return hash
}

func RandomEpochKeys(t *testing.T) crypto.EpochKeys {
	var epochKeys crypto.EpochKeys
	for i := 0; i < jamtime.TimeslotsPerEpoch; i++ {
		epochKeys[i] = RandomBandersnatchPublicKey(t)
	}
	return epochKeys
}

func RandomTicketProof(t *testing.T) [784]byte {
	var hash [784]byte
	_, err := rand.Read(hash[:])
	require.NoError(t, err)
	return hash
}
