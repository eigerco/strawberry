package crypto

import (
	"crypto/ed25519"
	"github.com/eigerco/strawberry/internal/jamtime"
)

type Ed25519PublicKey struct{
	 ed25519.PublicKey
}
type Ed25519PrivateKey ed25519.PrivateKey
type BlsKey [BLSSize]byte
type BandersnatchPublicKey [BandersnatchSize]byte
type BandersnatchSignature [96]byte
type MetadataKey [MetadataSize]byte
type RingCommitment [BandersnatchRingSize]byte
type EpochKeys [jamtime.TimeslotsPerEpoch]BandersnatchPublicKey
type ValidatorKey struct {
	Bandersnatch BandersnatchPublicKey
	Ed25519      Ed25519PublicKey
	Bls          BlsKey
	Metadata     MetadataKey
}
