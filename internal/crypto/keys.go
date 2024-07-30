package crypto

import (
	"crypto/ed25519"
	"github.com/eigerco/strawberry/internal/time"
)

type Ed25519PublicKey ed25519.PublicKey
type Ed25519PrivateKey ed25519.PrivateKey
type BlsKey [BLSSize]byte
type BandersnatchKey [BandersnatchSize]byte
type MetadataKey [MetadataSize]byte
type RingCommitment [BandersnatchRingSize]byte
type EpochKeys [time.TimeslotsPerEpoch]BandersnatchKey
