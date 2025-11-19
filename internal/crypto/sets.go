package crypto

import "github.com/eigerco/strawberry/internal/crypto/ed25519"

type ED25519PublicKeySet map[[Ed25519PublicSize]byte]struct{}

func (set ED25519PublicKeySet) Add(key ed25519.PublicKey) {
	set[[Ed25519PublicSize]byte(key)] = struct{}{}
}

func (set ED25519PublicKeySet) Has(key ed25519.PublicKey) bool {
	_, ok := set[[Ed25519PublicSize]byte(key)]
	return ok
}
