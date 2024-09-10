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

var seed2 = crypto.BandersnatchSeedKey{
	0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
	0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30,
	0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
	0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F, 0x40,
}

func TestSignAndVerify(t *testing.T) {
	pk1, err := NewPrivateKeyFromSeed(seed)
	require.NoError(t, err)

	message := []byte("Test message")

	signature1, err := pk1.Sign(message)
	require.NoError(t, err)

	publicKey1, err := pk1.Public()
	require.NoError(t, err)

	pk2, err := NewPrivateKeyFromSeed(seed2)
	require.NoError(t, err)

	publicKey2, err := pk2.Public()
	require.NoError(t, err)

	isValid := VerifySignature(signature1, message, publicKey1)
	require.True(t, isValid)

	// invalid signature from second key
	isInvalid := VerifySignature(signature1, message, publicKey2)
	require.False(t, isInvalid)

}

func TestGenerateAndVerifyVrfProof(t *testing.T) {
	pk1, err := NewPrivateKeyFromSeed(seed)
	require.NoError(t, err)

	pk2, err := NewPrivateKeyFromSeed(seed2)
	require.NoError(t, err)

	data := []byte("test data")
	context := []byte("context")

	// Valid VRF Proof
	proof, err := pk1.GenerateVrfProof(data, context)
	require.NoError(t, err)

	pubKey1, err := pk1.Public()
	require.NoError(t, err)

	valid := VerifyVrfProof(proof, data, context, pubKey1)
	require.True(t, valid)

	// Invalid VRF Proof - Changed Data
	proof, err = pk1.GenerateVrfProof(data, context)
	require.NoError(t, err)

	pubKey1, err = pk1.Public()
	require.NoError(t, err)

	invalidData := []byte("invalid data")
	valid = VerifyVrfProof(proof, invalidData, context, pubKey1)
	require.False(t, valid)

	// Invalid VRF Proof - Changed Context
	proof, err = pk1.GenerateVrfProof(data, context)
	require.NoError(t, err)

	pubKey1, err = pk1.Public()
	require.NoError(t, err)

	invalidContext := []byte("invalid context")
	valid = VerifyVrfProof(proof, data, invalidContext, pubKey1)
	require.False(t, valid)

	// Invalid VRF Proof - Different Key
	proof, err = pk1.GenerateVrfProof(data, context)
	require.NoError(t, err)

	pubKey2, err := pk2.Public()
	require.NoError(t, err)

	valid = VerifyVrfProof(proof, data, context, pubKey2)
	require.False(t, valid)

}
