package crypto

import (
	"crypto/ed25519"
)

type Ed25519PublicKey ed25519.PublicKey
type Ed25519PrivateKey ed25519.PrivateKey

type BlsKey [BLSSize]byte
type BandersnatchKey [BandersnatchSize]byte
