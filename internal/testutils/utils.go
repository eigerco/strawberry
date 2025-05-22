package testutils

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"iter"
	mathRand "math/rand"
	"strings"
	"testing"

	"github.com/eigerco/strawberry/internal/jamtime"

	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/crypto/bandersnatch"
	"github.com/stretchr/testify/require"
)

func RandomTimeslot() jamtime.Timeslot {
	return jamtime.Timeslot(RandomUint32())
}

func RandomUint16() uint16 {
	return uint16(RandomUint32() & 0xFFFF)
}

func RandomUint32() uint32 {
	return mathRand.Uint32()
}

func RandomUint64() uint64 {
	return mathRand.Uint64()
}

func RandomHash(t *testing.T) crypto.Hash {
	hash := make([]byte, crypto.HashSize)
	_, err := rand.Read(hash)
	require.NoError(t, err)
	return crypto.Hash(hash)
}

func RandomBandersnatchOutputHash(t *testing.T) crypto.BandersnatchOutputHash {
	hash := make([]byte, crypto.HashSize)
	_, err := rand.Read(hash)
	require.NoError(t, err)
	return crypto.BandersnatchOutputHash(hash)
}

func RandomED25519Keys(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return ed25519.GenerateKey(rand.Reader)
}

func RandomED25519PublicKey(t *testing.T) ed25519.PublicKey {
	key := ed25519.PublicKey(make([]byte, crypto.Ed25519PublicSize))
	_, err := rand.Read(key)
	require.NoError(t, err)
	return key
}

func RandomBandersnatchPublicKey(t *testing.T) crypto.BandersnatchPublicKey {
	privateKey := RandomBandersnatchPrivateKey(t)
	publicKey, err := bandersnatch.Public(privateKey)
	require.NoError(t, err)
	return publicKey
}

func RandomBandersnatchPrivateKey(t *testing.T) crypto.BandersnatchPrivateKey {
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
	privateKey := RandomBandersnatchPrivateKey(t)
	hash := make([]byte, 96)
	_, err := rand.Read(hash)
	require.NoError(t, err)
	signature, err := bandersnatch.Sign(privateKey, hash, hash)
	require.NoError(t, err)
	return signature
}

func RandomBandersnatchRingCommitment(t *testing.T) crypto.RingCommitment {
	hash := make([]byte, crypto.BandersnatchRingSize)
	_, err := rand.Read(hash)
	require.NoError(t, err)
	return crypto.RingCommitment(hash)
}

func RandomEd25519Signature(t *testing.T) crypto.Ed25519Signature {
	var hash crypto.Ed25519Signature
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

// Helper to decode a hex string beginning with "0x". Fails the test if the
// string can't be decoded.
func MustFromHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.TrimPrefix(s, "0x"))
	require.NoError(t, err)
	return b
}

func RandomBytes(t *testing.T, ln uint32) []byte {
	t.Helper()
	bb := make([]byte, ln)
	_, err := rand.Read(bb)
	require.NoError(t, err)
	return bb
}

// RandomSlice creates a slice of type T using generator function generatorFn between 1 and 100
func RandomSlice[T any](t *testing.T, start, end int32, generatorFn func(t *testing.T) T) iter.Seq[T] {
	t.Helper()
	return func(yield func(T) bool) {
		// range between 1 and maxRandomSliceLength, cases with zero items should be tested separately
		for range mathRand.Int31n(end-start) + start {
			yield(generatorFn(t))
		}
	}
}
