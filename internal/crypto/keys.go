package crypto

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/eigerco/strawberry/internal/jamtime"
)

type Ed25519PublicKey struct {
	ed25519.PublicKey
}
type C [][32]byte

type Ed25519PrivateKey ed25519.PrivateKey
type BlsKey [BLSSize]byte
type BandersnatchSeedKey [BandersnatchSize]byte
type BandersnatchSecretKey [BandersnatchSize]byte
type BandersnatchPublicKey [BandersnatchSize]byte
type BandersnatchSignature [96]byte
type VrfProof [VrfProofSize]byte
type VrfOutput [32]byte
type RingVrfSignature [VrfProofSize]byte
type MetadataKey [MetadataSize]byte
type RingCommitment [BandersnatchRingSize]byte
type EpochKeys [jamtime.TimeslotsPerEpoch]BandersnatchPublicKey
type ValidatorKey struct {
	Bandersnatch BandersnatchPublicKey
	Ed25519      Ed25519PublicKey
	Bls          BlsKey
	Metadata     MetadataKey
}

func (h Ed25519PublicKey) MarshalJSON() ([]byte, error) {
	return json.Marshal(fmt.Sprintf("0x%s", hex.EncodeToString(h.PublicKey[:])))
}

func (c C) MarshalJSON() ([]byte, error) {
	var encoded []string
	for _, b := range c {
		encoded = append(encoded, fmt.Sprintf("0x%s", hex.EncodeToString(b[:])))
	}

	return json.Marshal(encoded)
}

func (h BandersnatchSignature) MarshalJSON() ([]byte, error) {
	return json.Marshal(fmt.Sprintf("0x%s", hex.EncodeToString(h[:])))
}

func (h BandersnatchPublicKey) MarshalJSON() ([]byte, error) {
	return json.Marshal(fmt.Sprintf("0x%s", hex.EncodeToString(h[:])))
}
