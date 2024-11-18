package crypto

import (
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/sha3"
)

type Hash [HashSize]byte

func HashData(data []byte) Hash {
	hash := blake2b.Sum256(data)
	return hash
}

// KeccakData hashes the input data using Keccak-256
func KeccakData(data []byte) Hash {
	hash := sha3.NewLegacyKeccak256()
	hash.Write(data)
	hashed := hash.Sum(nil)

	var result Hash
	copy(result[:], hashed)
	return result
}
