package bandersnatch

import (
	"testing"

	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/stretchr/testify/require"
)

var seed = crypto.BandersnatchSeedKey{
	0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
	0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
	0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
	0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
}

func TestSignAndVerify(t *testing.T) {
	sk, err := NewPrivateKeyFromSeed(seed)
	require.NoError(t, err)
	pk, err := Public(sk)
	require.NoError(t, err)

	vrfInputData := []byte("vrf data")
	auxData := []byte("aux data")
	sig, err := Sign(sk, vrfInputData, auxData)
	require.NoError(t, err)

	ok, outputHash := Verify(pk, vrfInputData, auxData, sig)
	require.True(t, ok)

	outputHash2, err := OutputHash(sig)
	require.NoError(t, err)
	require.Equal(t, outputHash, outputHash2)
}
