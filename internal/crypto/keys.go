package crypto

import (
	"crypto/ed25519"

	"github.com/eigerco/strawberry/internal/jamtime"
)

type Ed25519Signature [Ed25519SignatureSize]byte
type BlsKey [BLSSize]byte
type BandersnatchSeedKey [BandersnatchSize]byte
type BandersnatchPrivateKey [BandersnatchSize]byte
type BandersnatchPublicKey [BandersnatchSize]byte

// TODO this is a tmp variable to hold the value of 33 bytes key that polkadot-sdk uses
// We should remove this after we fix the bandersnatch implementation
type BandersnatchSerializedPublicKey [BandersnatchSerializedSize]byte
type BandersnatchSignature [96]byte
type BandersnatchOutputHash [32]byte
type RingVrfSignature [VrfProofSize]byte
type MetadataKey [MetadataSize]byte
type RingCommitment [BandersnatchRingSize]byte
type EpochKeys [jamtime.TimeslotsPerEpoch]BandersnatchPublicKey
type ValidatorKey struct {
	Bandersnatch BandersnatchPublicKey
	Ed25519      ed25519.PublicKey
	Bls          BlsKey
	Metadata     MetadataKey
}
