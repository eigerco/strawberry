package crypto

import "golang.org/x/crypto/blake2b"

type Hash [HashSize]byte

func HashData(data []byte) Hash {
	hash := blake2b.Sum256(data)
	return hash
}
