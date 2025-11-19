package crypto

import (
	"bytes"

	"github.com/eigerco/strawberry/internal/crypto/ed25519"

	"github.com/eigerco/strawberry/internal/jamtime"
)

type Ed25519Signature [Ed25519SignatureSize]byte
type BlsKey [BLSSize]byte
type BandersnatchSeedKey [BandersnatchSize]byte
type BandersnatchPrivateKey [BandersnatchSize]byte

type BandersnatchPublicKey [BandersnatchSize]byte

func (b BandersnatchPublicKey) TicketOrKeyType() {}

type BandersnatchSignature [96]byte
type BandersnatchOutputHash [32]byte
type RingVrfSignature [VrfProofSize]byte
type MetadataKey [MetadataSize]byte
type RingCommitment [BandersnatchRingSize]byte

type EpochKeys [jamtime.TimeslotsPerEpoch]BandersnatchPublicKey

func (e EpochKeys) TicketsOrKeysType() {}

type ValidatorKey struct {
	Bandersnatch BandersnatchPublicKey
	Ed25519      ed25519.PublicKey
	Bls          BlsKey
	Metadata     MetadataKey
}

func (vk ValidatorKey) IsEmpty() bool {
	// Check if Ed25519 is empty slice or all zeros
	edKeyEmpty := len(vk.Ed25519) == 0 || bytes.Equal(vk.Ed25519, make([]byte, len(vk.Ed25519)))

	return vk.Bandersnatch == BandersnatchPublicKey{} &&
		edKeyEmpty &&
		vk.Bls == BlsKey{} &&
		vk.Metadata == MetadataKey{}
}
