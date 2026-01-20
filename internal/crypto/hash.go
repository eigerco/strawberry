package crypto

import (
	"encoding/hex"
	"io"
	"log"
	"strings"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/sha3"
)

type Hash [HashSize]byte

// UnmarshalJAM implements the JAM codec Unmarshaler interface.
func (h *Hash) UnmarshalJAM(r io.Reader) error {
	_, err := io.ReadFull(r, h[:])
	return err
}

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

// StringToHex converts a hex string to a byte slice
func StringToHex(s string) ([]byte, error) {
	// Remove 0x prefix if present
	s = strings.TrimPrefix(s, "0x")

	// Decode hex string
	bytes, err := hex.DecodeString(s)
	if err != nil {
		log.Printf("Error decoding hex string '%s': %v", s, err)
		return nil, err
	}
	return bytes, nil
}
