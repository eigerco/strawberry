package safrole

import (
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/time"
)

type Ed25519Key [crypto.Ed25519PublicSize]byte
type BlsKey [crypto.BLSSize]byte
type BandersnatchKey [crypto.BandersnatchSize]byte
type MetadataKey [crypto.MetadataSize]byte
type GammaZ [crypto.BandersnatchRingSize]byte
type EpochKeys [time.TimeslotsPerEpoch]BandersnatchKey
