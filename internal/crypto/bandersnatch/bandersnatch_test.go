package bandersnatch

import (
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/stretchr/testify/require"
	"testing"
)

var seed = crypto.BandersnatchSeedKey{
	0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
	0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
	0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
	0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
}

func TestSignAndVerify(t *testing.T) {
	pk, err := NewPrivateKeyFromSeed(seed)
	require.NoError(t, err)

	message := []byte("Test message")

	signature, err := pk.Sign(message)
	require.NoError(t, err)

	publicKey, err := pk.Public()
	require.NoError(t, err)

	t.Run("ValidSignature", func(t *testing.T) {
		isValid := VerifySignature(signature, message, publicKey)
		require.True(t, isValid)
	})

	t.Run("InvalidMessageSignature", func(t *testing.T) {
		invalidMessage := []byte("Invalid message")
		isInvalid := VerifySignature(signature, invalidMessage, publicKey)
		require.False(t, isInvalid)
	})
}

func TestGenerateAndVerifyVrfProof(t *testing.T) {
	t.Run("Valid VRF Proof", func(t *testing.T) {
		pk, err := NewPrivateKeyFromSeed(seed)
		require.NoError(t, err)

		data := []byte("test data")
		context := []byte("context")

		proof, err := pk.GenerateVrfProof(data, context)
		require.NoError(t, err)

		pubKey, err := pk.Public()
		require.NoError(t, err)

		valid := VerifyVrfProof(proof, data, context, pubKey)
		require.True(t, valid)
	})

	t.Run("Invalid VRF Proof - Changed Data", func(t *testing.T) {
		pk, err := NewPrivateKeyFromSeed(seed)
		require.NoError(t, err)

		data := []byte("test data")
		context := []byte("context")

		proof, err := pk.GenerateVrfProof(data, context)
		require.NoError(t, err)

		pubKey, err := pk.Public()
		require.NoError(t, err)

		invalidData := []byte("invalid data")
		valid := VerifyVrfProof(proof, invalidData, context, pubKey)
		require.False(t, valid)
	})

	t.Run("Invalid VRF Proof - Changed Context", func(t *testing.T) {
		pk, err := NewPrivateKeyFromSeed(seed)
		require.NoError(t, err)

		data := []byte("test data")
		context := []byte("context")

		proof, err := pk.GenerateVrfProof(data, context)
		require.NoError(t, err)

		pubKey, err := pk.Public()
		require.NoError(t, err)

		invalidContext := []byte("invalid context")
		valid := VerifyVrfProof(proof, data, invalidContext, pubKey)
		require.False(t, valid)
	})

}
