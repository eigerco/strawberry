package safrole

import (
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/time"
)

type MetadataKey [crypto.MetadataSize]byte
type GammaZ [crypto.BandersnatchRingSize]byte
type EpochKeys [time.TimeslotsPerEpoch]crypto.BandersnatchKey