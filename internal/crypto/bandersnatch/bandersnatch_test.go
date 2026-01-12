package bandersnatch

import (
	"encoding/binary"
	"testing"

	"github.com/eigerco/strawberry/internal/constants"
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/stretchr/testify/require"
)

// Creates a seed from an uint.
func uintToSeed(i uint) (seed crypto.BandersnatchSeedKey) {
	binary.LittleEndian.PutUint32(seed[:], uint32(i))
	return seed
}

func TestInitRingSize(t *testing.T) {
	// Confirm that the ring size is being correctly intialized within the init() fn.
	require.Equal(t, uint(constants.NumberOfValidators), GetRingSize())
}

func TestSignAndVerify(t *testing.T) {
	sk, err := NewPrivateKeyFromSeed(uintToSeed(1))
	require.NoError(t, err)
	pk, err := Public(sk)
	require.NoError(t, err)

	vrfInputData := []byte("foo")
	auxData := []byte("bar")
	sig, err := Sign(sk, vrfInputData, auxData)
	require.NoError(t, err)

	ok, outputHash := Verify(pk, vrfInputData, auxData, sig)
	require.True(t, ok)

	outputHash2, err := OutputHash(sig)
	require.NoError(t, err)
	require.Equal(t, outputHash, outputHash2)
}

func TestRingSignAndVerify(t *testing.T) {
	// Setup a ring using the index in the loop as a seed.
	ring := []crypto.BandersnatchPublicKey{}
	for i := uint(0); i < GetRingSize(); i++ {
		seed := uintToSeed(i)

		sk, err := NewPrivateKeyFromSeed(seed)
		require.NoError(t, err)

		pk, err := Public(sk)
		require.NoError(t, err)

		ring = append(ring, pk)
	}

	// Including some zero'd out public keys that should be replaced with
	// padding points.
	ring[4] = crypto.BandersnatchPublicKey{}
	ring[5] = crypto.BandersnatchPublicKey{}

	var proverIdx uint = 3
	proverSk, err := NewPrivateKeyFromSeed(uintToSeed(proverIdx))
	require.NoError(t, err)
	proverPk := ring[proverIdx]

	prover, err := NewRingProver(proverSk, ring, proverIdx)
	require.NoError(t, err)
	defer prover.Free()

	verifier, err := NewRingVerifier(ring)
	require.NoError(t, err)
	defer verifier.Free()

	commitment, err := verifier.Commitment()
	if err != nil {
		require.NoError(t, err)
	}

	vrfInputData := []byte("foo")
	auxData := []byte("bar")

	ringSignature, err := prover.Sign(vrfInputData, auxData)
	require.NoError(t, err)

	// Check that we can verify with only the commitment and not using the ring at all.
	verifierOnly, err := NewRingVerifier([]crypto.BandersnatchPublicKey{})
	require.NoError(t, err)
	defer verifierOnly.Free()

	ok, ringOutputHash := verifierOnly.Verify(vrfInputData, auxData, commitment, ringSignature)
	require.True(t, ok)

	// Sign the same vrf input data using the regular bandersnatch signature,
	// with different aux data.
	differentAuxData := []byte("baz")

	signature, err := Sign(proverSk, vrfInputData, differentAuxData)
	require.NoError(t, err)

	ok, outputHash := Verify(proverPk, vrfInputData, differentAuxData, signature)
	require.True(t, ok)

	// Should still have the same output hash, since both signatures used the
	// same vrf input data.
	require.Equal(t, ringOutputHash, outputHash)
}
