package crypto

import (
	"crypto/ed25519"
	"github.com/eigerco/strawberry/internal/jamtime"
)

type Ed25519PublicKey struct {
	ed25519.PublicKey
}
type Ed25519PrivateKey ed25519.PrivateKey
type Ed25519Signature [Ed25519SignatureSize]byte
type BlsKey [BLSSize]byte
type BandersnatchSeedKey [BandersnatchSize]byte
type BandersnatchSecretKey [BandersnatchSize]byte
type BandersnatchPublicKey [BandersnatchSize]byte

// TODO this is a tmp variable to hold the value of 33 bytes key that polkadot-sdk uses
// We should remove this after we fix the bandersnatch implementation
type BandersnatchSerializedPublicKey [BandersnatchSerializedSize]byte
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
